import React, { useEffect, useRef, useState } from "react";
import {
  DataGrid,
  GridColDef,
  GridRenderCellParams,
  GridRowSelectionModel,
} from "@mui/x-data-grid";
import {
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Fab,
  IconButton,
  Tooltip,
} from "@mui/material";
import {
  DeleteSweep,
  Visibility,
  RestartAlt,
  Add as AddIcon,
  Delete as DeleteIcon,
  Memory,
  Info,
  DataObject,
  ViewModule,
  Source,
  Fingerprint,
  CloudUpload as CloudUploadIcon,
  Create as CreateIcon,
  Download as DownloadIcon,
} from "@mui/icons-material";
import LinearProgressBar from "../LinearProgressBar";
import axiosInstance from "../../utils/axiosInstance";
import { YaraRule, YaraRuleSet } from "../../types";
import { useSnackbar } from "../SnackbarProvider";
import YaraRuleCreationDialog from "../Dialogs/YaraRuleCreationDialog";
import YaraRuleEditDialog from "../Dialogs/YaraRuleEditDialog";

interface YaraRuleListProps {
  yararuleset?: YaraRuleSet;
}

function YaraRuleList({ yararuleset }: YaraRuleListProps) {
  const { display_message } = useSnackbar();
  const [isConnected, setIsConnected] = useState(false);
  const [yararuleData, setYararuleData] = useState<YaraRule[]>([]);
  const [allYaraRuleSets, setAllYaraRuleSets] = useState<YaraRuleSet[]>([]);
  const [openDeleteDialog, setOpenDeleteDialog] = useState(false);
  const [openRestartDialog, setOpenRestartDialog] = useState(false);
  const [openViewDialog, setOpenViewDialog] = useState(false);
  const [openCreationDialog, setOpenCreationDialog] = useState(false);
  const [openNewRuleDialog, setOpenNewRuleDialog] = useState(false);
  const [selectedYaraRule, setSelectedYaraRule] = useState<YaraRule | null>(
    null
  );
  const [deleteMultiple, setDeleteMultiple] = useState(false);
  const [yaraRuleToDelete, setYaraRuleToDelete] = useState<YaraRule | null>(
    null
  );
  const [yaraRuleToRestart, setYaraRuleToRestart] = useState<YaraRule | null>(
    null
  );

  const ws = useRef<WebSocket | null>(null);
  const retryInterval = useRef<number | null>(null);

  const [selectionModel, setSelectionModel] =
    useState<GridRowSelectionModel>({
      type: "include",
      ids: new Set<number>(),
    });

  const selectedIds = [...(selectionModel as any).ids] as number[];

  useEffect(() => {
    const fetchYaraRules = async () => {
      try {
        const response = await axiosInstance.get("/api/yararules/");
        const data: YaraRule[] = response.data;
        const yaraRulesUpdated = data.map((d) => ({
          ...d,
          ruleset_name: d.linked_yararuleset?.name || "No ruleset",
        }));

        if (yararuleset) {
          const filteredData = yaraRulesUpdated.filter((rule: YaraRule) => {
            const rulesetId =
              typeof rule.linked_yararuleset === "object"
                ? rule.linked_yararuleset?.id
                : (rule.linked_yararuleset as unknown as number) || null;
            return rulesetId === yararuleset.id;
          });
          setYararuleData(filteredData);
        } else {
          setYararuleData(yaraRulesUpdated);
        }
        setIsConnected(true);
      } catch (error) {
        console.error("Error fetching data", error);
        setIsConnected(false);
      }
    };

    const fetchAllRuleSets = async () => {
      try {
        const response = await axiosInstance.get("/api/yararulesets/");
        setAllYaraRuleSets(response.data);
      } catch (error) {
        console.error("Error fetching rulesets", error);
      }
    };

    fetchYaraRules();
    fetchAllRuleSets();
  }, [yararuleset]);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/yararules/`;

    const connectWebSocket = () => {
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        console.log("WebSocket connected (yararules)");
        setIsConnected(true);
        if (retryInterval.current) {
          clearInterval(retryInterval.current);
          retryInterval.current = null;
        }
      };

      ws.current.onclose = () => {
        console.log("WebSocket disconnected (yararules)");
        setIsConnected(false);
        if (!retryInterval.current) {
          retryInterval.current = window.setTimeout(connectWebSocket, 5000);
          console.log("Attempting to reconnect to WebSocket (yararules)...");
        }
      };

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const status = data.status;
          const message: YaraRule = data.message;

          if (status === "created" || status === "updated") {
            setYararuleData((prevData) => {
              const exists = prevData.some((r) => r.id === message.id);
              if (exists) {
                return prevData.map((r) => (r.id === message.id ? message : r));
              } else {
                return [...prevData, message];
              }
            });
          } else if (status === "deleted") {
            setYararuleData((prevData) =>
              prevData.filter((r) => r.id !== message.id)
            );
            setSelectionModel((prev: any) => ({
              type: "include",
              ids: new Set([...prev.ids].filter((id: number) => id !== message.id)),
            }));
          }
        } catch (err) {
          console.error("Failed to parse WS message (yararules):", err);
        }
      };

      ws.current.onerror = (error) => {
        console.error("WebSocket error (yararules):", error);
      };
    };

    connectWebSocket();

    return () => {
      if (ws.current) ws.current.close();
      if (retryInterval.current) clearInterval(retryInterval.current);
    };
  }, []);

  const handleDeleteClick = (row: YaraRule) => {
    setYaraRuleToDelete(row);
    setDeleteMultiple(false);
    setOpenDeleteDialog(true);
  };

  const handleRestartClick = (row: YaraRule) => {
    setYaraRuleToRestart(row);
    setOpenRestartDialog(true);
  };

  const handleOpenDeleteMultipleDialog = () => {
    setDeleteMultiple(true);
    setOpenDeleteDialog(true);
  };

  const handleConfirmRestart = async () => {
    if (!yaraRuleToRestart) return;

    try {
      await axiosInstance.post(
        `/api/yararules/${yaraRuleToRestart.id}/recompile/`
      );
      display_message("success", "Compilation restarted");
    } catch (error) {
      display_message("error", `Failed to restart compilation: ${error}`);
    } finally {
      setOpenRestartDialog(false);
    }
  };

  const handleConfirmDelete = async () => {
    try {
      if (deleteMultiple) {
        const idsToDelete = [...(selectionModel as any).ids] as number[];
        // Use bulk delete endpoint to avoid per-delete ruleset recompilation
        await axiosInstance.post(`/api/yararules/bulk_delete/`, { ids: idsToDelete });
        display_message("success", "Selected yara rules deleted successfully");
        setSelectionModel({ type: "include", ids: new Set<number>() });
      } else if (yaraRuleToDelete) {
        await axiosInstance.delete(`/api/yararules/${yaraRuleToDelete.id}/`);
        display_message("success", "Yara rule deleted successfully");
      }

      const response = await axiosInstance.get("/api/yararules/");
      const data: YaraRule[] = response.data;
      const yaraRulesUpdated = data.map((d) => ({
        ...d,
        ruleset_name: d.linked_yararuleset?.name || "No ruleset",
      }));

      if (yararuleset) {
        const filteredData = yaraRulesUpdated.filter((rule: YaraRule) => {
          const rulesetId =
            typeof rule.linked_yararuleset === "object"
              ? rule.linked_yararuleset?.id
              : (rule.linked_yararuleset as unknown as number) || null;
          return rulesetId === yararuleset.id;
        });
        setYararuleData(filteredData);
      } else {
        setYararuleData(yaraRulesUpdated);
      }
    } catch (error) {
      display_message(
        "error",
        `Error deleting the selected yara rule: ${String(error)}`
      );
    } finally {
      setOpenDeleteDialog(false);
    }
  };

  const handleViewClick = (row: YaraRule) => {
    setSelectedYaraRule(row);
    setOpenViewDialog(true);
  };

  const handleNewRuleClick = () => {
    const newRule: YaraRule = {
      id: 0,
      name: "new_rule",
      rule_content: `rule new_rule {
    meta:
        description = "New YARA rule"
        author = ""
        date = "${new Date().toISOString().split("T")[0]}"
    
    strings:
        $string1 = "example"
    
    condition:
        $string1
}`,
      description: "New YARA rule",
      linked_yararuleset: yararuleset || null,
      status: 0,
      is_active: true,
    };

    setSelectedYaraRule(newRule);
    setOpenNewRuleDialog(true);
  };

  const handleUpdateSuccess = (updatedRule: YaraRule) => {
    const fetchYaraRules = async () => {
      try {
        const response = await axiosInstance.get("/api/yararules/");
        const data: YaraRule[] = response.data;
        const yaraRulesUpdated = data.map((d) => ({
          ...d,
          ruleset_name: d.linked_yararuleset?.name || "No ruleset",
        }));

        if (yararuleset) {
          const filteredData = yaraRulesUpdated.filter(
            (rule: YaraRule) =>
              (typeof rule.linked_yararuleset === "object"
                ? rule.linked_yararuleset?.id
                : (rule.linked_yararuleset as unknown as number) || null) ===
              yararuleset.id
          );
          setYararuleData(filteredData);
        } else {
          setYararuleData(yaraRulesUpdated);
        }
      } catch (error) {
        console.error("Error fetching data", error);
      }
    };

    fetchYaraRules();
  };

  const handleDownloadRule = async (ruleId: number, ruleName: string) => {
    try {
      const response = await axiosInstance.get(
        `/api/yararules/${ruleId}/download/`,
        {
          responseType: "blob",
        }
      );

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `${ruleName}.yar`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      display_message("success", "Rule downloaded successfully");
    } catch (error) {
      display_message("error", `Failed to download rule: ${error}`);
    }
  };

  const columns: GridColDef[] = [
    {
      field: "name",
      headerName: "Yara Rule Name",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Memory style={{ marginRight: 8 }} color="info" />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "description",
      headerName: "Description",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Info style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "ruleset_name",
      headerName: "Ruleset",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <ViewModule style={{ marginRight: 8 }} />
          {params.value || "No ruleset"}
        </div>
      ),
      flex: 2,
    },
    {
      field: "source",
      headerName: "Source",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Source style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
    },
    {
      field: "etag",
      headerName: "Identifier",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Fingerprint style={{ marginRight: 8 }} color="secondary" />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "status",
      headerName: "Status",
      renderCell: (params: GridRenderCellParams) =>
        params.value === 100 ? (
          <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
            <Chip label="Compiled" size="small" color="success" variant="outlined" />
          </div>
        ) : params.value === -1 ? (
          <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
            <Chip label="Empty content" size="small" color="warning" variant="outlined" />
          </div>
        ) : params.value === -2 ? (
          <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
            <Chip label="Syntax error" size="small" color="error" variant="outlined" />
          </div>
        ) : params.value === -3 ? (
          <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
            <Chip label="Error compiling" size="small" color="error" variant="outlined" />
          </div>
        ) : params.value === -4 ? (
          <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
            <Chip label="Generic error" size="small" color="error" variant="outlined" />
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
            <LinearProgressBar value={Number(params.value)} />
          </div>
        ),
      flex: 1,
    },
    {
      field: "actions",
      headerName: "Actions",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Tooltip title="View/Edit Rule" placement="right">
            <IconButton edge="end" aria-label="view" onClick={() => handleViewClick(params.row)}>
              <Visibility />
            </IconButton>
          </Tooltip>
          <Tooltip title="Download Rule" placement="top">
            <IconButton
              edge="end"
              aria-label="download"
              onClick={() => handleDownloadRule(params.row.id, params.row.name)}
              disabled={params.row.status !== 100}
            >
              <DownloadIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Restart compilation" placement="right">
            <IconButton
              edge="end"
              aria-label="restart"
              onClick={() => handleRestartClick(params.row)}
              disabled={params.row.status > 0 && params.row.status < 100}
            >
              <RestartAlt />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete" placement="right">
            <IconButton
              edge="end"
              aria-label="delete"
              onClick={() => handleDeleteClick(params.row)}
              disabled={params.row.status > 0 && params.row.status < 100}
            >
              <DeleteSweep />
            </IconButton>
          </Tooltip>
        </div>
      ),
      flex: 1.5,
    },
  ];

  return (
    <>
      {/* FAB: upload/import */}
      <Tooltip title="Upload YARA rules from file or GitHub" placement="left">
        <Fab
          color="primary"
          aria-label="upload"
          onClick={() => {
            setOpenCreationDialog(true);
          }}
          style={{ position: "fixed", bottom: 16, right: 16 }}
        >
          <CloudUploadIcon />
        </Fab>
      </Tooltip>

      {/* FAB: create new rule */}
      <Tooltip title="Create new YARA rule" placement="left">
        <Fab
          color="secondary"
          aria-label="create"
          onClick={handleNewRuleClick}
          style={{ position: "fixed", bottom: 16, right: 80 }}
        >
          <CreateIcon />
        </Fab>
      </Tooltip>

      <YaraRuleEditDialog
        open={openViewDialog}
        onClose={() => setOpenViewDialog(false)}
        yaraRule={selectedYaraRule}
        onUpdateSuccess={handleUpdateSuccess}
        yaraRuleSets={allYaraRuleSets}
      />

      <YaraRuleEditDialog
        open={openNewRuleDialog}
        onClose={() => setOpenNewRuleDialog(false)}
        yaraRule={selectedYaraRule}
        onUpdateSuccess={(newRule) => {
          display_message("success", "YARA rule created successfully");
          handleUpdateSuccess(newRule);
          setOpenNewRuleDialog(false);
        }}
        yaraRuleSets={allYaraRuleSets}
      />

      <YaraRuleCreationDialog
        open={openCreationDialog}
        onClose={() => {
          setOpenCreationDialog(false);
        }}
        onCreateSuccess={(rule) => {
          display_message("success", "YARA rule created successfully");
          handleUpdateSuccess(rule);
        }}
        onImportSuccess={() => {
          display_message("success", "GitHub import completed");
          handleUpdateSuccess({} as YaraRule);
        }}
        yara_ruleset={yararuleset}
      />

      <DataGrid
        getRowHeight={() => "auto"}
        disableRowSelectionOnClick
        rows={yararuleData}
        columns={columns}
        loading={!isConnected}
        checkboxSelection
        disableRowSelectionExcludeModel
        rowSelectionModel={selectionModel as any}
        onRowSelectionModelChange={(newSelection) => {
          setSelectionModel(newSelection as any);
        }}
      />

      {(selectionModel as any).ids && (selectionModel as any).ids.size > 0 && (
        <Fab
          color="secondary"
          aria-label="delete"
          style={{ position: "fixed", bottom: 80, right: 16 }}
          onClick={handleOpenDeleteMultipleDialog}
        >
          <DeleteIcon />
        </Fab>
      )}

      <Dialog
        open={openDeleteDialog}
        onClose={() => setOpenDeleteDialog(false)}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">{`Delete ${
          deleteMultiple ? "Selected Yara Rules" : "Yara Rule"
        }`}</DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {`Are you sure you want to delete ${
              deleteMultiple ? "these yara rules" : "this yara rule"
            }?`}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDeleteDialog(false)} color="primary">
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

export default YaraRuleList;