import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { DataGrid, GridColDef, GridRenderCellParams } from "@mui/x-data-grid";
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

function RulesetList() {
  const navigate = useNavigate();
  const [checked, setChecked] = useState<number[]>([]);
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedRuleset, setSelectedRuleset] = useState<YaraRuleSet | null>(null);
  const [openRestartDialog, setOpenRestartDialog] = useState<boolean>(false);
  const [rulesetDialogOpen, setRulesetDialogOpen] = useState(false);
  const [rulesetData, setRulesetData] = useState<YaraRuleSet[]>([]);
  const [deleteMultiple, setDeleteMultiple] = useState(false);

  const { display_message } = useSnackbar();
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
        const message = data.message;

        if (status === "created") {
          setRulesetData((prevData) => {
            const exists = prevData.some(
              (rulesetItem) => rulesetItem.id === message.id,
            );
            if (exists) {
              return prevData.map((rulesetItem) =>
                rulesetItem.id === message.id ? message : rulesetItem,
              );
            } else {
              return [...prevData, message];
            }
          });
        } else if (status === "updated") {
          setRulesetData((prevData) =>
            prevData.map((rulesetItem) =>
              rulesetItem.id === message.id ? message : rulesetItem,
            ),
          );
        } else if (status === "deleted") {
          setRulesetData((prevData) =>
            prevData.filter((rulesetItem) => rulesetItem.id !== message.id),
          );
          setChecked([]);
        }
      };

      ws.current.onerror = (error) => {
        console.log("WebSocket error:", error);
      };
    };

    connectWebSocket();

    axiosInstance
      .get("/api/yararulesets/")
      .then((response) => {
        setRulesetData(response.data);
      })
      .catch((error) => {
        display_message("error", "Error fetching the ruleset data.");
        console.error("Error fetching ruleset data:", error);
      });

    return () => {
      if (ws.current) {
        ws.current.close();
      }
      if (retryInterval.current) {
        clearTimeout(retryInterval.current);
      }
    };
  }, [display_message]);

  const handleCreateSuccess = () => {
    display_message("success", "Ruleset created.");
  };

  const handleDeleteClick = (row: YaraRuleSet) => {
    setSelectedRuleset(row);
    setOpenDialog(true);
    setDeleteMultiple(false);
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
    } else if (deleteMultiple) {
      handleDeleteSelected();
    }
  };

  const handleDeleteSelected = async () => {
    try {
      await Promise.all(
        checked.map((id) => axiosInstance.delete(`/api/yararulesets/${id}/`)),
      );
      display_message("success", "Selected rulesets deleted.");
      setChecked([]);
    } catch {
      display_message("error", "Error deleting selected rulesets");
    } finally {
      setOpenDialog(false);
    }
  };

  const handleOpenDeleteMultipleDialog = () => {
    setDeleteMultiple(true);
    setOpenDialog(true);
  };

  const handleToggle = (id: number) => {
    navigate(`/yararulesets/${id}`);
  };

  const handleRestartClick = (row: YaraRuleSet) => {
    setSelectedRuleset(row);
    setOpenRestartDialog(true);
  };

  const handleConfirmRestart = async () => {
    if (selectedRuleset) {
      const id: number = selectedRuleset.id;
      try {
        await axiosInstance.post(`/api/yararulesets/tasks/restart/`, { id });
        display_message("success", "Compiling restarted");
      } catch (error) {
        display_message("error", `Error restarting the compilation: ${error}`);
      } finally {
        setOpenRestartDialog(false);
      }
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
          {params.value || 'No description'}
        </div>
      ),
      flex: 2,
    },
    {
      field: "status",
      headerName: "Status",
      renderCell: (params: GridRenderCellParams) =>
        params.value === 100 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="Compiled"
              size="small"
              color="success"
              variant="outlined"
            />
          </div>
        ) : params.value === -1 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="No active rules"
              size="small"
              color="warning"
              variant="outlined"
            />
          </div>
        ) : params.value === -2 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="No valid rules"
              size="small"
              color="warning"
              variant="outlined"
            />
          </div>
        ) : params.value === -3 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="Error compiling"
              size="small"
              color="error"
              variant="outlined"
            />
          </div>
        ) : 
        (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <LinearProgressBar value={Number(params.value)} />
          </div>
        ),
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
              <IconButton
                edge="end"
                aria-label="open"
                onClick={() => handleToggle(params.row.id)}
              >
                <Link />
              </IconButton>
            </Tooltip>	
            <Tooltip title="Restart compilation" placement="right">
              <IconButton
                edge="end"
                aria-label="restart"
                onClick={() => handleRestartClick(params.row)}
                disabled={isCompiling}
              >
                <RestartAlt />
              </IconButton>
            </Tooltip>
            <Tooltip title="Delete Ruleset">
              <IconButton
                edge="end"
                aria-label="delete"
                onClick={() => handleDeleteClick(params.row)}
                disabled={isCompiling}
              >
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
      <DataGrid
        rowHeight={60}
        disableRowSelectionOnClick
        columns={columns}
        rows={rulesetData}
        loading={!isConnected}
        checkboxSelection
        onRowSelectionModelChange={(selection) => {
          setChecked(selection as number[]);
        }}
      />
      <Fab
        color="primary"
        aria-label="add"
        style={{ position: "fixed", bottom: 16, right: 16 }}
        onClick={() => setRulesetDialogOpen(true)}
      >
        <AddIcon />
      </Fab>
      {checked.length > 0 && (
        <Fab
          color="secondary"
          aria-label="delete"
          style={{ position: "fixed", bottom: 90, right: 16 }}
          onClick={handleOpenDeleteMultipleDialog}
        >
          <DeleteIcon />
        </Fab>
      )}
      <AddRuleSetDialog
        open={rulesetDialogOpen}
        onClose={() => setRulesetDialogOpen(false)}
        onCreateSuccess={handleCreateSuccess}
      />
      <Dialog
        open={openDialog}
        onClose={() => setOpenDialog(false)}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">{`Delete ${
          deleteMultiple ? "Selected Rulesets" : "Ruleset"
        }`}</DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {`Are you sure you want to delete ${
              deleteMultiple ? "these rulesets" : "this ruleset"
            }?`}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)} color="primary">
            Cancel
          </Button>
          <Button onClick={handleConfirmDelete} color="primary" autoFocus>
            Yes
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={openRestartDialog}
        onClose={() => setOpenRestartDialog(false)}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">Restart the compilation</DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            You are about to restart the compilation, confirm ?
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenRestartDialog(false)} color="primary">
            Cancel
          </Button>
          <Button onClick={handleConfirmRestart} color="primary" autoFocus>
            Restart
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

export default RulesetList;