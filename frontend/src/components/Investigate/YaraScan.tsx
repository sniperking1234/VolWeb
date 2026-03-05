import React, { useState, useCallback, useEffect, useMemo, useRef } from "react";
import {
  Box,
  Button,
  Paper,
  TextField,
  Typography,
  Grid,
  List,
  ListItem,
  ListItemText,
  Checkbox,
  FormControlLabel,
  Divider,
  Alert,
  Chip,
  CircularProgress,
  IconButton,
} from "@mui/material";
import Slide from "@mui/material/Slide";
import { 
  Security, 
  PlayArrow, 
  CheckCircle,
  Delete,
  Close as CloseIcon,
} from "@mui/icons-material";
import SearchIcon from '@mui/icons-material/Search';
import { DataGrid, GridColDef, useGridApiRef } from "@mui/x-data-grid";
import axiosInstance from "../../utils/axiosInstance";
import { YaraRuleSet, YaraRule, TaskData } from "../../types";
import { useSnackbar } from "../SnackbarProvider";

interface YaraScanProps {
  evidenceId: string;
}

interface ScanHistory {
  id: string;
  timestamp: string;
  ruleset_name: string;
  results: any[];
  description: string;
  scanName: string;
  plugin_name?: string;
}

const YaraScan: React.FC<YaraScanProps> = ({ evidenceId }) => {
  const { display_message } = useSnackbar();
  const ws = useRef<WebSocket | null>(null);
  const apiRef = useGridApiRef();
  const [rulesets, setRulesets] = useState<YaraRuleSet[]>([]);
  const [rules, setRules] = useState<YaraRule[]>([]);
  const [selectedRulesets, setSelectedRulesets] = useState<number[]>([]);
  const [selectedRules, setSelectedRules] = useState<number[]>([]);
  const [scanResults, setScanResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [hasResults, setHasResults] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanHistory[]>([]);
  const [rulesetSearch, setRulesetSearch] = useState<string>("");
  const [ruleSearch, setRuleSearch] = useState<string>("");
  const [currentScanId, setCurrentScanId] = useState<string>("");
  const [transitioning, setTransitioning] = useState(false);

  const fetchYaraData = useCallback(async () => {
    try {
      setLoading(true);
      
      const rulesetsResponse = await axiosInstance.get("/api/yararulesets/");
      const compiledRulesets = rulesetsResponse.data.filter(
        (ruleset: YaraRuleSet) => ruleset.status === 100
      );
      setRulesets(compiledRulesets);

      const rulesResponse = await axiosInstance.get("/api/yararules/");
  
      const validRules = rulesResponse.data.filter(
        (rule: YaraRule) => rule.status === 100 && rule.is_active
      );
      
      setRules(validRules);
    } catch (error) {
      display_message("error", `Failed to fetch YARA data: ${error}`);
    } finally {
      setLoading(false);
    }
  }, [display_message]);

  const loadScanHistoryFromBackend = useCallback(async (forceLoadResults = false) => {
    try {
      const response = await axiosInstance.get(`/api/evidence/${evidenceId}/yarascan/history/`);
      if (response.data && response.data.length > 0) {
        const scan = response.data[0];
        const description = scan.description || "";
        
        let scanName = "Latest YARA Scan";
        
        if (description.includes('using')) {
          const usingMatch = description.match(/using (.+?) - /);
          if (usingMatch && usingMatch[1]) {
            const scanInfo = usingMatch[1];
            
            if (scanInfo.match(/\d+ individual rule/)) {
              const ruleCount = scanInfo.match(/(\d+) individual rule/)?.[1] || "Unknown";
              scanName = `${ruleCount} Individual Rule${parseInt(ruleCount) !== 1 ? 's' : ''}`;
            } 
            else if (scanInfo.startsWith('ruleset:')) {
              scanName = scanInfo.replace('ruleset: ', '');
            }
            else if (scanInfo.startsWith('rulesets:')) {
              const rulesetsStr = scanInfo.replace('rulesets: ', '');
              const rulesetList = rulesetsStr.split(', ');
              if (rulesetList.length > 2) {
                scanName = `${rulesetList.slice(0, 2).join(', ')}, +${rulesetList.length - 2}`;
              } else {
                scanName = rulesetsStr;
              }
            }
            else if (scanInfo === 'All Active Rules') {
              scanName = 'All Active Rules';
            }
            else {
              scanName = scanInfo;
            }
          }
        }
        
        const backendHistory = [{
          id: "latest",
          timestamp: new Date().toISOString(),
          ruleset_name: scanName,
          results: scan.artefacts || [],
          description: description,
          scanName: scanName,
          plugin_name: scan.name
        }];
        
        setScanHistory(backendHistory);
        
        if ((forceLoadResults || !hasResults) && backendHistory.length > 0) {
          setScanResults(backendHistory[0].results);
          setCurrentScanId(backendHistory[0].id);
          setHasResults(true);
        }
      } else {
        setScanHistory([]);
      }
    } catch (error) {
      console.error("Error loading scan history from backend:", error);
      display_message("error", "Failed to load scan history");
    }
  }, [evidenceId, hasResults, display_message]);

  const deleteScan = useCallback(async (scan: ScanHistory) => {
    try {
      await axiosInstance.delete(`/api/evidence/${evidenceId}/yarascan/${scan.plugin_name}/`);
      display_message("success", "Scan deleted successfully");
      
      if (currentScanId === scan.id) {
        setHasResults(false);
        setScanResults([]);
        setCurrentScanId("");
      }
      
      loadScanHistoryFromBackend(false);
    } catch (error) {
      console.error("Error deleting scan:", error);
      display_message("error", "Failed to delete scan");
    }
  }, [evidenceId, currentScanId, display_message, loadScanHistoryFromBackend]);

  const deleteCurrentScan = useCallback(async () => {
    if (scanHistory.length > 0) {
      await deleteScan(scanHistory[0]);
    }
  }, [scanHistory, deleteScan]);

  const loadScanFromHistory = useCallback(async (scan: ScanHistory) => {
    setTransitioning(true);
    
    try {
      if (scan.plugin_name) {
        const response = await axiosInstance.get(
          `/api/evidence/${evidenceId}/plugin/${scan.plugin_name}/`
        );
        if (response.data && response.data.artefacts) {
          setScanResults(response.data.artefacts);
          setCurrentScanId(scan.id);
          setHasResults(true);
        }
      } else {
        setScanResults(scan.results);
        setCurrentScanId(scan.id);
        setHasResults(true);
      }
    } catch (error) {
      console.error("Error loading scan from history:", error);
      setScanResults(scan.results);
      setCurrentScanId(scan.id);
      setHasResults(true);
    }
    
    setTimeout(() => {
      setTransitioning(false);
    }, 300);
  }, [evidenceId]);

  const checkIfYaraScanTaskRunning = useCallback(async () => {
    try {
      const response = await axiosInstance.get(`/api/evidence/${evidenceId}/tasks/`);
      const tasksData: TaskData[] = response.data;

      const isYaraScanTaskRunning = tasksData.some((task) => {
        return (
          task.task_name === "volatility_engine.tasks.start_yarascan" &&
          task.status === "STARTED"
        );
      });

      setProcessing(isYaraScanTaskRunning);
    } catch (error) {
      console.error("Error checking YaraScan task status", error);
    }
  }, [evidenceId]);

  useEffect(() => {
    fetchYaraData();
    loadScanHistoryFromBackend(false);
    checkIfYaraScanTaskRunning();
  }, [fetchYaraData, checkIfYaraScanTaskRunning]);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/engine/${evidenceId}/`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log("YaraScan WebSocket connected");
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log("YaraScan WebSocket message:", data);

      const message = data.message;
      if (message.name === "yarascan") {
        if (message.status === "finished") {
          setProcessing(false);
          if (message.result !== "false") {
            setTimeout(async () => {
              await loadScanHistoryFromBackend(true);
              display_message("success", "YaraScan completed successfully");
            }, 1500);
          } else {
            display_message("warning", "YaraScan did not return any results");
          }
        }
      }
    };

    ws.current.onclose = () => {
      console.log("YaraScan WebSocket disconnected");
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [evidenceId, loadScanHistoryFromBackend, display_message]);

  const handleRulesetToggle = (rulesetId: number) => {
    setSelectedRulesets((prev) =>
      prev.includes(rulesetId)
        ? prev.filter((id) => id !== rulesetId)
        : [...prev, rulesetId]
    );
  };

  const handleRuleToggle = (ruleId: number) => {
    setSelectedRules((prev) =>
      prev.includes(ruleId)
        ? prev.filter((id) => id !== ruleId)
        : [...prev, ruleId]
    );
  };

  const handleRunYaraScan = async () => {
    if (selectedRulesets.length === 0 && selectedRules.length === 0) {
      display_message("warning", "Please select at least one ruleset or rule");
      return;
    }

    try {
      setProcessing(true);
      await axiosInstance.post(`/api/evidence/tasks/yarascan/`, {
        id: evidenceId,
        rulesets: selectedRulesets,
        rules: selectedRules,
      });
      display_message("info", "YaraScan task started");
    } catch (error) {
      display_message("error", `Failed to start YaraScan: ${error}`);
      setProcessing(false);
    }
  };

  const handleNewScan = () => {
    setTransitioning(true);
    setTimeout(() => {
      setHasResults(false);
      setTransitioning(false);
    }, 300);
  };

  // Helper function to decode hex string to readable text
  const decodeHexString = (hexStr: string): string => {
    if (!hexStr || typeof hexStr !== 'string') return '';
    
    try {
      // Match pattern like b'\x00\x00=\x00' or similar
      const matches = hexStr.match(/\\x([0-9a-fA-F]{2})/g);
      if (!matches) return '';
      
      let result = '';
      for (const match of matches) {
        const hex = match.replace('\\x', '');
        const charCode = parseInt(hex, 16);
        // Only add printable ASCII characters
        if (charCode >= 32 && charCode <= 126) {
          result += String.fromCharCode(charCode);
        } else if (charCode === 0) {
          // Skip null bytes
          continue;
        } else {
          result += '.';
        }
      }
      return result || '(non-printable)';
    } catch (e) {
      return '(decode error)';
    }
  };

  // DataGrid columns for scan results - same structure as PluginDataGrid
  const resultColumns: GridColDef[] = useMemo(() => {
    if (scanResults.length === 0) return [];
    
    const columns = Object.keys(scanResults[0])
      .filter(key => key !== 'id' && key !== '__children')
      .map(key => ({
        field: key,
        headerName: key,
        flex: 1,
        minWidth: 150,
        renderCell: (params) => {
          if (key === "File output" && params.value !== "Disabled") {
            return (
              <Button
                variant="outlined"
                size="small"
                onClick={() => window.open(`/media/${evidenceId}/${params.value}`)}
              >
                Download
              </Button>
            );
          }

          if (key === "Disasm" || key === "Hexdump") {
            return <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{params.value}</pre>;
          }

          return typeof params.value === "boolean" ? (
            params.value ? (
              <Checkbox checked={true} color="success" />
            ) : (
              <IconButton color="error">
                <CloseIcon />
              </IconButton>
            )
          ) : params.value !== null ? (
            <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{params.value}</span>
          ) : (
            ""
          );
        },
      }));
    
    // Add decoded value column after Value column
    const valueIndex = columns.findIndex(col => col.field === 'Value');
    if (valueIndex !== -1) {
      columns.splice(valueIndex + 1, 0, {
        field: 'DecodedValue',
        headerName: 'Decoded Value',
        flex: 1,
        minWidth: 150,
        renderCell: (params) => {
          const valueField = params.row.Value;
          const decoded = decodeHexString(valueField);
          return <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{decoded}</span>;
        },
      });
    }
    
    return columns;
  }, [scanResults, evidenceId]);

  const autosizeOptions = useMemo(
    () => ({
      columns: [...resultColumns].map((col) => col.headerName ?? ""),
      includeOutliers: true,
      includeHeaders: true,
    }),
    [resultColumns],
  );

  // Add this useEffect to call autosizeColumns after the data is loaded
  useEffect(() => {
    if (!transitioning && scanResults.length > 0) {
      const timeoutId = setTimeout(() => {
        if (apiRef.current) {
          apiRef.current.autosizeColumns(autosizeOptions);
        }
      }, 200);
      return () => clearTimeout(timeoutId);
    }
  }, [transitioning, scanResults, apiRef, autosizeOptions]);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="100vh">
        <CircularProgress />
      </Box>
    );
  }

  if (!hasResults) {
    return (
      <Slide direction="left" in={!transitioning} timeout={300}>
        <Box sx={{ p: 3 }}>
          <Paper elevation={3} sx={{ p: 3 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
              <Typography variant="h5" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Security color="primary" />
                YARA Scan Configuration
              </Typography>
              {scanHistory.length > 0 && (
                <Chip
                  label="View Latest Scan Results"
                  variant="outlined"
                  color="primary"
                  onClick={() => {
                    loadScanFromHistory(scanHistory[0]);
                  }}
                  clickable
                />
              )}
            </Box>
            
            <Grid container spacing={3}>
              <Grid size={6}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="h6">Available Rulesets</Typography>
                    <TextField
                      size="small"
                      placeholder="Search rulesets"
                      value={rulesetSearch}
                      onChange={(e) => setRulesetSearch(e.target.value)}
                      InputProps={{
                        startAdornment: <SearchIcon fontSize="small" sx={{ mr: 1 }} />,
                      }}
                      sx={{ width: 240 }}
                    />
                  </Box>
                <Divider sx={{ mb: 2 }} />
                
                {rulesets.length === 0 ? (
                  <Alert severity="info">
                    No compiled rulesets available. Please compile rulesets first.
                  </Alert>
                ) : (
                  <Paper variant="outlined" sx={{ maxHeight: 400, overflow: "auto", p: 2 }}>
                    <List dense>
                      {rulesets
                        .filter(rs => rs.name.toLowerCase().includes(rulesetSearch.toLowerCase()))
                        .map((ruleset) => (
                        <ListItem key={ruleset.id} sx={{ py: 1 }}>
                          <Checkbox
                            checked={selectedRulesets.includes(ruleset.id)}
                            onChange={() => handleRulesetToggle(ruleset.id)}
                          />
                          <ListItemText
                            primary={ruleset.name}
                            secondary={`${ruleset.rules?.length || 0} rules`}
                          />
                          <CheckCircle color="success" fontSize="small" />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                )}
              </Grid>

              <Grid size={6}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                  <Typography variant="h6">
                    Individual Rules
                  </Typography>
                  <TextField
                    size="small"
                    placeholder="Search rules"
                    value={ruleSearch}
                    onChange={(e) => setRuleSearch(e.target.value)}
                    InputProps={{
                      startAdornment: <SearchIcon fontSize="small" sx={{ mr: 1 }} />,
                    }}
                    sx={{ width: 240 }}
                  />
                </Box>
                <Divider sx={{ mb: 2 }} />
                
                {rules.length === 0 ? (
                  <Alert severity="info">
                    No active individual rules available.
                  </Alert>
                ) : (
                  <Paper variant="outlined" sx={{ maxHeight: 400, overflow: "auto", p: 2 }}>
                    <List dense>
                      {rules
                        .filter(r => r.name.toLowerCase().includes(ruleSearch.toLowerCase()))
                        .map((rule) => (
                        <ListItem key={rule.id} sx={{ py: 1 }}>
                          <Checkbox
                            checked={selectedRules.includes(rule.id)}
                            onChange={() => handleRuleToggle(rule.id)}
                          />
                          <ListItemText
                            primary={rule.name}
                            secondary={`${
                              rule.linked_yararuleset
                                ? typeof rule.linked_yararuleset === 'object' && rule.linked_yararuleset !== null
                                    ? rule.linked_yararuleset.name 
                                    : "No ruleset"
                                : "None"
                            }`}
                          />
                          <CheckCircle color="success" fontSize="small" />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                )}
              </Grid>
            </Grid>

            <Box mt={4} display="flex" justifyContent="center" alignItems="center" gap={2}>
              <Button
                variant="outlined"
                size="large"
                color="error"
                startIcon={processing ? <CircularProgress size={20} /> : <PlayArrow />}
                onClick={handleRunYaraScan}
                disabled={processing || (selectedRulesets.length === 0 && selectedRules.length === 0)}
              >
                {processing ? "Processing..." : "Run YARA Scan"}
              </Button>
              
              <Typography variant="body2" color="text.secondary">
                Selected: {selectedRulesets.length} rulesets, {selectedRules.length} rules
              </Typography>
            </Box>
          </Paper>
        </Box>
      </Slide>
    );
  }

  return (
    <Slide direction="right" in={!transitioning} timeout={300}>
      <Box sx={{ flexGrow: 1 }}>
        <Box sx={{ mb: 2, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Typography variant="h5" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Security color="primary" />
            YARA Scan Results
          </Typography>
          <Box sx={{ display: "flex", gap: 1 }}>
            {scanHistory.length > 0 && (
              <Button
                variant="outlined"
                color="error"
                startIcon={<Delete />}
                onClick={deleteCurrentScan}
              >
                Delete Scan
              </Button>
            )}
            <Button
              variant="contained"
              onClick={handleNewScan}
            >
              New Scan
            </Button>
          </Box>
        </Box>
        
        <Box sx={{ height: "calc(100vh - 200px)", width: "100%" }}>
          <DataGrid
            disableDensitySelector
            showToolbar
            rows={scanResults.map((result, index) => ({ ...result, id: index }))}
            columns={resultColumns}
            density="compact"
            sx={{ 
              height: "100%",
              '& .MuiDataGrid-cell': {
                padding: '8px',
                whiteSpace: 'normal',
                wordWrap: 'break-word',
                lineHeight: 'normal',
              },
              '& .MuiDataGrid-columnHeader': {
                whiteSpace: 'normal',
                lineHeight: 'normal',
              }
            }}
            getRowId={(row) => row.id}
            pagination
            loading={transitioning}
            autosizeOnMount
            autosizeOptions={autosizeOptions}
            apiRef={apiRef}
            getRowHeight={() => "auto"}
          />
        </Box>
      </Box>
    </Slide>
  );
};

export default YaraScan;