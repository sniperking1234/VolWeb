import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { DataGrid, GridColDef, GridRenderCellParams, GridRowSelectionModel } from "@mui/x-data-grid";
import { Download as DownloadIcon } from "@mui/icons-material";
import {
  IconButton,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Button,
  Tooltip,
  Fab,
  Chip,
  TextField,
  Box,
} from "@mui/material";
import {
  DeleteSweep,
  Link,
  Work,
  Info,
  Add as AddIcon,
  Delete as DeleteIcon,
  RestartAlt,
} from "@mui/icons-material";
import axiosInstance from "../../utils/axiosInstance";
import AddRuleSetDialog from "../Dialogs/YaraRuleSetCreationDialog";
import LinearProgressBar from "../LinearProgressBar";
import { YaraRuleSet } from "../../types";
import { useSnackbar } from "../SnackbarProvider";
import SearchIcon from '@mui/icons-material/Search';

function RulesetList() {
  const navigate = useNavigate();
  const { display_message } = useSnackbar();

  const [selectionModel, setSelectionModel] = useState<GridRowSelectionModel>({ type: "include", ids: new Set<number>() });

  const [openDialog, setOpenDialog] = useState(false);
  const [selectedRuleset, setSelectedRuleset] = useState<YaraRuleSet | null>(null);
  const [openRestartDialog, setOpenRestartDialog] = useState<boolean>(false);
  const [rulesetDialogOpen, setRulesetDialogOpen] = useState(false);
  const [rulesetData, setRulesetData] = useState<YaraRuleSet[]>([]);
  const [rulesetFilter, setRulesetFilter] = useState<string>("");
  const [deleteMultiple, setDeleteMultiple] = useState(false);

  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);
  const retryInterval = useRef<number | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/yararulesets/`;

    const connectWebSocket = () => {
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        console.log("WebSocket connected");
        setIsConnected(true);
        if (retryInterval.current) {
          clearTimeout(retryInterval.current);
          retryInterval.current = null;
        }
      };

      ws.current.onclose = () => {
        console.log("WebSocket disconnected");
        setIsConnected(false);
        if (!retryInterval.current) {
          retryInterval.current = window.setTimeout(connectWebSocket, 2000);
          console.log("Attempting to reconnect to WebSocket...");
        }
      };

      ws.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        const status = data.status;
        const message: YaraRuleSet = data.message;

        if (status === "created") {
          setRulesetData((prevData) => {
            const exists = prevData.some((item) => item.id === message.id);
            return exists ? prevData.map((item) => (item.id === message.id ? message : item)) : [...prevData, message];
          });
        } else if (status === "updated") {
          setRulesetData((prevData) => prevData.map((item) => (item.id === message.id ? message : item)));
        } else if (status === "deleted") {
          setRulesetData((prevData) => prevData.filter((item) => item.id !== message.id));
          setSelectionModel((prev) => ({
            type: "include",
            ids: new Set([...prev.ids].filter((id) => id !== message.id)),
          }));
        }
      };

      ws.current.onerror = (error) => console.log("WebSocket error:", error);
    };

    connectWebSocket();

    axiosInstance
      .get("/api/yararulesets/")
      .then((res) => setRulesetData(res.data))
      .catch((err) => {
        display_message("error", "Error fetching the ruleset data.");
        console.error(err);
      });

    return () => {
      if (ws.current) ws.current.close();
      if (retryInterval.current) clearTimeout(retryInterval.current);
    };
  }, [display_message]);

  const handleCreateSuccess = () => display_message("success", "Ruleset created.");

  const handleDeleteClick = (row: YaraRuleSet) => {
    setSelectedRuleset(row);
    setOpenDialog(true);
    setDeleteMultiple(false);
  };

  const handleDeleteSelected = async () => {
    try {
      const selectedIds = [...selectionModel.ids] as number[];
      await Promise.all(selectedIds.map((id) => axiosInstance.delete(`/api/yararulesets/${id}/`)));
      display_message("success", "Selected rulesets deleted.");
      setSelectionModel({ type: "include", ids: new Set() });
    } catch {
      display_message("error", "Error deleting selected rulesets");
    } finally {
      setOpenDialog(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (selectedRuleset && !deleteMultiple) {
      try {
        await axiosInstance.delete(`/api/yararulesets/${selectedRuleset.id}/`);
        display_message("success", "Ruleset deleted.");
      } catch {
        display_message("error", "Error deleting ruleset");
      } finally {
        setOpenDialog(false);
        setSelectedRuleset(null);
      }
    } else if (deleteMultiple) handleDeleteSelected();
  };

  const handleOpenDeleteMultipleDialog = () => {
    setDeleteMultiple(true);
    setOpenDialog(true);
  };

  const handleToggle = (id: number) => navigate(`/yararulesets/${id}`);

  const handleRestartClick = (row: YaraRuleSet) => {
    setSelectedRuleset(row);
    setOpenRestartDialog(true);
  };

  const handleConfirmRestart = async () => {
    if (selectedRuleset) {
      try {
        await axiosInstance.post(`/api/yararulesets/tasks/restart/`, { id: selectedRuleset.id });
        display_message("success", "Compiling restarted");
      } catch (error) {
        display_message("error", `Error restarting the compilation: ${error}`);
      } finally {
        setOpenRestartDialog(false);
      }
    }
  };

  const handleDownloadRuleset = async (rulesetId: number, rulesetName: string) => {
    try {
      const response = await axiosInstance.get(`/api/yararulesets/${rulesetId}/download/`, { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `${rulesetName}.yar`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      display_message("success", "Ruleset downloaded successfully");
    } catch (error) {
      display_message("error", `Failed to download ruleset: ${error}`);
    }
  };

  const columns: GridColDef[] = [
    {
      field: "name",
      headerName: "Ruleset Name",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <Work style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "description",
      headerName: "Description",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <Info style={{ marginRight: 8 }} />
          {params.value || "No description"}
        </div>
      ),
      flex: 2,
    },
    {
      field: "status",
      headerName: "Status",
      renderCell: (params: GridRenderCellParams) => {
        const value = params.value;
        if (value === 100)
          return <Chip label="Compiled" size="small" color="success" variant="outlined" />;
        if (value === -1) return <Chip label="No active rules" size="small" color="warning" variant="outlined" />;
        if (value === -2) return <Chip label="No valid rules" size="small" color="warning" variant="outlined" />;
        if (value === -3) return <Chip label="Error compiling" size="small" color="error" variant="outlined" />;
        return <LinearProgressBar value={Number(value)} />;
      },
      flex: 1,
    },
    {
      field: "actions",
      headerName: "Actions",
      renderCell: (params: GridRenderCellParams) => {
        const isCompiling = params.row.status > 0 && params.row.status < 100;
        return (
          <>
            <Tooltip title="View Ruleset">
              <IconButton onClick={() => handleToggle(params.row.id)}>
                <Link />
              </IconButton>
            </Tooltip>
            <Tooltip title="Download Ruleset (.yar)">
              <span>
                <IconButton onClick={() => handleDownloadRuleset(params.row.id, params.row.name)} disabled={params.row.status !== 100}>
                  <DownloadIcon />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title="Restart compilation">
              <IconButton onClick={() => handleRestartClick(params.row)} disabled={isCompiling}>
                <RestartAlt />
              </IconButton>
            </Tooltip>
            <Tooltip title="Delete Ruleset">
              <IconButton onClick={() => handleDeleteClick(params.row)} disabled={isCompiling}>
                <DeleteSweep />
              </IconButton>
            </Tooltip>
          </>
        );
      },
      sortable: false,
      flex: 1,
    },
  ];

  return (
    <>
      <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <TextField
          size="small"
          placeholder="Search rulesets"
          value={rulesetFilter}
          onChange={(e) => setRulesetFilter(e.target.value)}
          InputProps={{ startAdornment: <SearchIcon fontSize="small" sx={{ mr: 1 }} /> }}
          sx={{ width: 360 }}
        />
      </Box>

      <DataGrid
        rowHeight={60}
        disableRowSelectionOnClick
        columns={columns}
        rows={rulesetData.filter(rs => rs.name.toLowerCase().includes(rulesetFilter.toLowerCase()))}
        loading={!isConnected}
        checkboxSelection
        disableRowSelectionExcludeModel
        rowSelectionModel={selectionModel}
        onRowSelectionModelChange={(newSelection) => setSelectionModel(newSelection)}
      />

      <Fab color="primary" aria-label="add" style={{ position: "fixed", bottom: 16, right: 16 }} onClick={() => setRulesetDialogOpen(true)}>
        <AddIcon />
      </Fab>

      {selectionModel.ids.size > 0 && (
        <Fab color="secondary" aria-label="delete" style={{ position: "fixed", bottom: 90, right: 16 }} onClick={handleOpenDeleteMultipleDialog}>
          <DeleteIcon />
        </Fab>
      )}

      <AddRuleSetDialog open={rulesetDialogOpen} onClose={() => setRulesetDialogOpen(false)} onCreateSuccess={handleCreateSuccess} />

      <Dialog open={openDialog} onClose={() => setOpenDialog(false)}>
        <DialogTitle>{`Delete ${deleteMultiple ? "Selected Rulesets" : "Ruleset"}`}</DialogTitle>
        <DialogContent>
          <DialogContentText>{`Are you sure you want to delete ${deleteMultiple ? "these rulesets" : "this ruleset"}?`}</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)} color="primary">Cancel</Button>
          <Button onClick={handleConfirmDelete} color="primary" autoFocus>Yes</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={openRestartDialog} onClose={() => setOpenRestartDialog(false)}>
        <DialogTitle>Restart the compilation</DialogTitle>
        <DialogContent>
          <DialogContentText>You are about to restart the compilation, confirm?</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenRestartDialog(false)} color="primary">Cancel</Button>
          <Button onClick={handleConfirmRestart} color="primary" autoFocus>Restart</Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

export default RulesetList;
