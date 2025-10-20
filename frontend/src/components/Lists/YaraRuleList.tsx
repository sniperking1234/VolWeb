import React, { useEffect, useState } from "react";
import { DataGrid, GridColDef, GridRenderCellParams } from "@mui/x-data-grid";
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
  const [checked, setChecked] = useState<number[]>([]);
  const [openDeleteDialog, setOpenDeleteDialog] = useState(false);
  const [openRestartDialog, setOpenRestartDialog] = useState(false);
  const [openViewDialog, setOpenViewDialog] = useState(false);
  const [openCreationDialog, setOpenCreationDialog] = useState(false);
  const [openNewRuleDialog, setOpenNewRuleDialog] = useState(false);
  const [selectedYaraRule, setSelectedYaraRule] = useState<YaraRule | null>(null);
  const [deleteMultiple, setDeleteMultiple] = useState(false);
  const [yaraRuleToDelete, setYaraRuleToDelete] = useState<YaraRule | null>(null);
  const [yaraRuleToRestart, setYaraRuleToRestart] = useState<YaraRule | null>(null);

  useEffect(() => {
    const fetchYaraRules = async () => {
      try {
        const response = await axiosInstance.get("/api/yararules/");
        const data = response.data;
        
        const yaraRulesUpdated = data.map((d: YaraRule) => ({
          ...d,
          ruleset_name: d.linked_yararuleset?.name || "No ruleset",
        }));

        if (yararuleset) {
          const filteredData = yaraRulesUpdated.filter(
            (rule: YaraRule) => {
              const rulesetId = typeof rule.linked_yararuleset === 'object' 
                ? rule.linked_yararuleset?.id 
                : rule.linked_yararuleset;
              return rulesetId === yararuleset.id;
            }
          );
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
      await axiosInstance.post(`/api/yararules/${yaraRuleToRestart.id}/recompile/`);
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
        for (const id of checked) {
          await axiosInstance.delete(`/api/yararules/${id}/`);
        }
        display_message("success", "Selected yara rules deleted successfully");
      } else if (yaraRuleToDelete) {
        await axiosInstance.delete(`/api/yararules/${yaraRuleToDelete.id}/`);
        display_message("success", "Yara rule deleted successfully");
      }

      const response = await axiosInstance.get("/api/yararules/");
      const data = response.data;
      const yaraRulesUpdated = data.map((d: YaraRule) => ({
        ...d,
        ruleset_name: d.linked_yararuleset?.name || "No ruleset",
      }));

      if (yararuleset) {
        const filteredData = yaraRulesUpdated.filter(
          (rule: YaraRule) => {
            // Compare by ID to handle both object and ID references
            const rulesetId = typeof rule.linked_yararuleset === 'object' 
              ? rule.linked_yararuleset?.id 
              : rule.linked_yararuleset;
            return rulesetId === yararuleset.id;
          }
        );
        setYararuleData(filteredData);
      } else {
        setYararuleData(yaraRulesUpdated);
      }
      setChecked([]);
    } catch (error) {
      display_message(
        "error",
        `Error deleting the selected yara rule: ${error}`,
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
    // Create a new empty rule for the editor
    const newRule: YaraRule = {
      id: 0, // Will be assigned by backend
      name: "new_rule",
      rule_content: `rule new_rule {
    meta:
        description = "New YARA rule"
        author = ""
        date = "${new Date().toISOString().split('T')[0]}"
    
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
    // Refresh the data after successful update
    const fetchYaraRules = async () => {
      try {
        const response = await axiosInstance.get("/api/yararules/");
        const data = response.data;

        const yaraRulesUpdated = data.map((d: YaraRule) => ({
          ...d,
          ruleset_name: d.linked_yararuleset?.name || "No ruleset",
        }));

        if (yararuleset) {
          const filteredData = yaraRulesUpdated.filter(
            (rule: YaraRule) => rule.linked_yararuleset?.id === yararuleset.id
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
      field: "rule_content",
      headerName: "Rule Content",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <DataObject style={{ marginRight: 8 }} />
          {params.value && params.value.length > 50 
            ? `${params.value.substring(0, 50)}...` 
            : params.value || 'No content'}
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
              label="Empty content"
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
              label="Syntax error"
              size="small"
              color="error"
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
        ) : params.value === -4 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="Generic error"
              size="small"
              color="error"
              variant="outlined"
            />
          </div>
        ) : (
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
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Tooltip title="View/Edit Rule" placement="right">
            <IconButton
              edge="end"
              aria-label="view"
              onClick={() => handleViewClick(params.row)}
            >
              <Visibility />
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
      {/* FAB for uploading/importing rules */}
      <Tooltip title="Upload YARA rules from file or GitHub" placement="left">
        <Fab
          color="primary"
          aria-label="upload"
          onClick={() => {
            setOpenCreationDialog(true);
          }}
          style={{ position: "fixed", bottom: "16px", right: "16px" }}
        >
          <CloudUploadIcon />
        </Fab>
      </Tooltip>
      
      {/* FAB for creating new rule from scratch */}
      <Tooltip title="Create new YARA rule" placement="left">
        <Fab
          color="secondary"
          aria-label="create"
          onClick={handleNewRuleClick}
          style={{ position: "fixed", bottom: "16px", right: "80px" }}
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
      
      {/* Dialog for creating new rule from scratch */}
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
        getRowHeight={() => 'auto'}
        disableRowSelectionOnClick
        rows={yararuleData}
        columns={columns}
        loading={!isConnected}
        checkboxSelection
        onRowSelectionModelChange={(newSelection) => {
          setChecked(newSelection as number[]);
        }}
      />
      
      {checked.length > 0 && (
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