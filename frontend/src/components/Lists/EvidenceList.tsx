import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  DataGrid,
  GridColDef,
  GridRenderCellParams,
  GridRowSelectionModel,
} from "@mui/x-data-grid";
import axiosInstance from "../../utils/axiosInstance";
import EvidenceCreationDialog from "../Dialogs/EvidenceCreationDialog";
import LinearProgressWithLabel from "../LinearProgressBar";
import {
  Chip,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Button,
  Fab,
} from "@mui/material";
import {
  Add as AddIcon,
  Memory,
  DeviceHub,
  Biotech,
  DeleteSweep,
  Link,
  Delete as DeleteIcon,
  RestartAlt,
  Fingerprint,
  Work,
  PlayArrow,
  Pause,
  Stop,
} from "@mui/icons-material";
import BindEvidenceDialog from "../Dialogs/BindEvidenceDialog";
import { Evidence } from "../../types";
interface EvidenceListProps {
  caseId?: number;
}
import { useSnackbar } from "../SnackbarProvider";

function EvidenceList({ caseId }: EvidenceListProps) {
  const navigate = useNavigate();
  const [evidenceData, setEvidenceData] = useState<Evidence[]>([]);
  const [openDeleteDialog, setOpenDeleteDialog] = useState<boolean>(false);
  const [openCreationDialog, setOpenCreationDialog] = useState<boolean>(false);
  const [openBindingDialog, setOpenBindingDialog] = useState<boolean>(false);
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(
    null,
  );
  const [deleteMultiple, setDeleteMultiple] = useState(false);

  const [selectionModel, setSelectionModel] = useState<GridRowSelectionModel>({
    type: "include",
    ids: new Set(),
  });

  const { display_message } = useSnackbar();

  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);
  const retryInterval = useRef<number | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/evidences/${caseId ? `${caseId}/` : ""}`;

    const connectWebSocket = () => {
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        console.log("WebSocket connected");
        setIsConnected(true);
        if (retryInterval.current) {
          clearInterval(retryInterval.current);
          retryInterval.current = null;
        }
      };

      ws.current.onclose = () => {
        console.log("WebSocket disconnected");
        setIsConnected(false);
        if (!retryInterval.current) {
          retryInterval.current = window.setTimeout(connectWebSocket, 5000);
          console.log("Attempting to reconnect to WebSocket...");
        }
      };

      ws.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        const status = data.status;
        const message = data.message;

        if (status === "created") {
          setEvidenceData((prevData) => {
            const exists = prevData.some(
              (evidence) => evidence.id === message.id,
            );
            if (exists) {
              return prevData.map((evidence) =>
                evidence.id === message.id ? message : evidence,
              );
            } else {
              return [...prevData, message];
            }
          });
        } else {
          setEvidenceData((prevData) =>
            prevData.filter((evidence) => evidence.id !== message.id),
          );
          setSelectionModel((prev) => ({
            type: "include",
            ids: new Set([...prev.ids].filter((id) => id !== message.id)),
          }));
        }
      };

      ws.current.onerror = (error) => {
        console.log("WebSocket error:", error);
      };
    };

    connectWebSocket();

    axiosInstance
      .get("/api/evidences/", { params: caseId ? { linked_case: caseId } : {} })
      .then((response) => {
        setEvidenceData(response.data);
      })
      .catch((error) => {
        display_message("error", `Error fetching evidence data: ${error}`);
        console.error("Error fetching evidence data:", error);
      });

    return () => {
      if (ws.current) {
        ws.current.close();
      }
      if (retryInterval.current) {
        clearInterval(retryInterval.current);
      }
    };
  }, [caseId, display_message]);

  const handleBindSuccess = () => {
    display_message("success", "Evidence binded.");
  };

  const handleToggle = (id: number) => {
    navigate(`/evidences/${id}`);
  };

  const handleDeleteClick = (row: Evidence) => {
    setSelectedEvidence(row);
    setOpenDeleteDialog(true);
    setDeleteMultiple(false);
  };

  const handleOpenDeleteMultipleDialog = () => {
    setDeleteMultiple(true);
    setOpenDeleteDialog(true);
  };

  const selectedIds = [...selectionModel.ids] as number[];
  const handleConfirmDelete = async () => {
    if (selectedEvidence && !deleteMultiple) {
      try {
        await axiosInstance.delete(`/api/evidences/${selectedEvidence.id}/`);
        display_message("success", "Evidence deleted.");
      } catch (error) {
        display_message("error", `Error deleting the evidence: ${error}`);
      } finally {
        setOpenDeleteDialog(false);
        setSelectedEvidence(null);
      }
    } else if (deleteMultiple) {
      handleDeleteSelected();
    }
  };

  const handlePlayClick = (evidence: Evidence) => {
    navigate(`/evidences/${evidence.id}?configure=true`);
  };

  const handlePause = async (evidence: Evidence) => {
    try {
      await axiosInstance.post("/api/evidence/tasks/pause/", { id: evidence.id });
      setEvidenceData((prev) =>
        prev.map((e) =>
          e.id === evidence.id ? { ...e, extraction_control: "paused" } : e,
        ),
      );
    } catch (error) {
      display_message("error", `Error pausing extraction: ${error}`);
    }
  };

  const handleResume = async (evidence: Evidence) => {
    try {
      await axiosInstance.post("/api/evidence/tasks/resume/", { id: evidence.id });
      setEvidenceData((prev) =>
        prev.map((e) =>
          e.id === evidence.id ? { ...e, extraction_control: "running" } : e,
        ),
      );
    } catch (error) {
      display_message("error", `Error resuming extraction: ${error}`);
    }
  };

  const handleStop = async (evidence: Evidence) => {
    try {
      await axiosInstance.post("/api/evidence/tasks/stop/", { id: evidence.id });
      setEvidenceData((prev) =>
        prev.map((e) =>
          e.id === evidence.id ? { ...e, extraction_control: "idle", status: 100 } : e,
        ),
      );
    } catch (error) {
      display_message("error", `Error stopping extraction: ${error}`);
    }
  };


  const handleDeleteSelected = async () => {
    try {
      await Promise.all(
        selectedIds.map((id) => axiosInstance.delete(`/api/evidences/${id}/`)),
      );
      display_message("success", "Selected evidences deleted.");
      setSelectionModel({ type: "include", ids: new Set() });
    } catch (error) {
      display_message(
        "error",
        `Error deleting the selected evidence: ${error}`,
      );
    } finally {
      setOpenDeleteDialog(false);
    }
  };

  const columns: GridColDef[] = [
    {
      field: "name",
      headerName: "Evidence Name",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Memory style={{ marginRight: 8 }} color="info" />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    ...(!caseId ? [{
      field: "linked_case_name",
      headerName: "Case",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Work style={{ marginRight: 8 }} color="primary" />
          <Chip
            label={params.value || `Case #${params.row.linked_case}`}
            color="primary"
            variant="outlined"
            size="small"
            onClick={() => navigate(`/cases/${params.row.linked_case}`)}
            style={{ cursor: 'pointer' }}
          />
        </div>
      ),
      flex: 0.8,
    }] : []),
    {
      field: "os",
      headerName: "Operating System",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <DeviceHub style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
      flex: 1,
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
        params.row.extraction_control === "paused" ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="Paused"
              size="small"
              color="warning"
              variant="outlined"
            />
          </div>
        ) : params.value === 100 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="success"
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
              label="Unsatisfied requirements"
              size="small"
              color="error"
              variant="outlined"
            />
          </div>
        ) : params.value === -2 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="Awaiting plugin selection"
              size="small"
              color="warning"
              variant="outlined"
            />
          </div>
        ) : (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <LinearProgressWithLabel value={Number(params.value)} />
          </div>
        ),
      flex: 1,
    },
    {
      field: "actions",
      headerName: "Actions",
      renderCell: (params: GridRenderCellParams) => {
        const s = params.row.status;
        const ec = params.row.extraction_control;
        const isRunning = s >= 0 && s < 100 && ec !== "paused";
        const isPaused = ec === "paused";
        const isExtracting = isRunning || isPaused;
        const isAwaiting = s === -2;

        return (
          <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
            <Tooltip title="Investigate" placement="left">
              <span>
                <IconButton
                  edge="end"
                  aria-label="open"
                  disabled={isAwaiting}
                  onClick={() => handleToggle(params.row.id)}
                >
                  <Biotech />
                </IconButton>
              </span>
            </Tooltip>
            {isAwaiting ? (
              <Tooltip title="Start analysis" placement="top">
                <IconButton
                  edge="end"
                  aria-label="play"
                  onClick={() => handlePlayClick(params.row)}
                >
                  <PlayArrow />
                </IconButton>
              </Tooltip>
            ) : isRunning ? (
              <>
                <Tooltip title="Pause" placement="top">
                  <IconButton
                    edge="end"
                    aria-label="pause"
                    onClick={() => handlePause(params.row)}
                  >
                    <Pause />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Stop" placement="top">
                  <IconButton
                    edge="end"
                    aria-label="stop"
                    onClick={() => handleStop(params.row)}
                  >
                    <Stop />
                  </IconButton>
                </Tooltip>
              </>
            ) : isPaused ? (
              <>
                <Tooltip title="Resume" placement="top">
                  <IconButton
                    edge="end"
                    aria-label="resume"
                    onClick={() => handleResume(params.row)}
                  >
                    <PlayArrow />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Stop" placement="top">
                  <IconButton
                    edge="end"
                    aria-label="stop"
                    onClick={() => handleStop(params.row)}
                  >
                    <Stop />
                  </IconButton>
                </Tooltip>
              </>
            ) : (
              <Tooltip title="Reconfigure" placement="top">
                <span>
                  <IconButton
                    edge="end"
                    aria-label="reconfigure"
                    onClick={() => navigate(`/evidences/${params.row.id}?configure=true`)}
                  >
                    <RestartAlt />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            <Tooltip title="Delete" placement="right">
              <span>
                <IconButton
                  edge="end"
                  aria-label="delete"
                  disabled={isExtracting}
                  onClick={() => handleDeleteClick(params.row)}
                >
                  <DeleteSweep />
                </IconButton>
              </span>
            </Tooltip>
          </div>
        );
      },
      flex: 1,
    },
  ];

  return (
    <>
      <Fab
        color="primary"
        aria-label="add"
        onClick={() => {
          setOpenCreationDialog(true);
        }}
        style={{ position: "fixed", bottom: "16px", right: "16px" }}
      >
        <AddIcon />
      </Fab>
      <EvidenceCreationDialog
        open={openCreationDialog}
        onClose={() => {
          setOpenCreationDialog(false);
        }}
        caseId={caseId}
      />
      <Fab
        color="secondary"
        aria-label="bind"
        onClick={() => {
          setOpenBindingDialog(true);
        }}
        style={{ position: "fixed", bottom: "16px", right: "80px" }}
      >
        <Link />
      </Fab>
      <BindEvidenceDialog
        open={openBindingDialog}
        onClose={() => {
          setOpenBindingDialog(false);
        }}
        onBindSuccess={handleBindSuccess}
        caseId={caseId}
      />

      {selectedIds.length > 0 && (
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
          deleteMultiple ? "Selected Evidences" : "Evidence"
        }`}</DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {`Are you sure you want to delete ${
              deleteMultiple ? "these evidences" : "this evidence"
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
      <DataGrid
        rowHeight={40}
        disableRowSelectionOnClick
        rows={evidenceData}
        columns={columns}
        loading={!isConnected}
        pagination
        disableRowSelectionExcludeModel
        checkboxSelection
        rowSelectionModel={selectionModel}
        onRowSelectionModelChange={(newSelection) => 
          setSelectionModel(newSelection)
        }
      />
    </>
  );
}

export default EvidenceList;
