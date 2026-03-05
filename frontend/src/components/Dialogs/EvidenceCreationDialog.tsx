import React, { useState, useEffect } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Autocomplete,
  CircularProgress,
} from "@mui/material";
import axiosInstance from "../../utils/axiosInstance";
import { Case } from "../../types";
import { useEvidenceUpload } from "../EvidenceUploadProvider";

interface EvidenceCreationDialogProps {
  open: boolean;
  onClose: () => void;
  caseId?: number;
}

const EvidenceCreationDialog: React.FC<EvidenceCreationDialogProps> = ({
  open,
  onClose,
  caseId,
}) => {
  const OS_OPTIONS = [
    { value: "windows", label: "Windows" },
    { value: "linux", label: "Linux" },
  ];

  const { uploadState, startUpload, cancelUpload } = useEvidenceUpload();

  const [os, setOs] = useState<string>("");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [cases, setCases] = useState<Case[]>([]);
  const [selectedEvidence, setSelectedEvidence] = useState<Case | null>(null);
  const [evidenceLoading, setEvidencesLoading] = useState<boolean>(false);

  useEffect(() => {
    if (open) {
      if (caseId) {
        setSelectedEvidence({ id: caseId } as Case);
        setEvidencesLoading(false);
      } else {
        fetchCases();
      }
    }
  }, [open, caseId]);

  const fetchCases = async () => {
    setEvidencesLoading(true);
    try {
      const response = await axiosInstance.get<Case[]>("/api/cases/");
      setCases(response.data);
    } catch (err) {
      console.error("Error fetching cases:", err);
      setError("Failed to load cases.");
    } finally {
      setEvidencesLoading(false);
    }
  };

  const handleUpload = () => {
    if (!os || !file || (!selectedEvidence && !caseId)) {
      setError("Please fill in all fields.");
      return;
    }

    const uploadCaseId = caseId || selectedEvidence?.id;
    if (!uploadCaseId) return;

    startUpload({ file, caseId: uploadCaseId, os });
    setOs("");
    setFile(null);
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth>
      <DialogTitle>Upload a new evidence</DialogTitle>
      <DialogContent>
        {evidenceLoading ? (
          <div style={{ textAlign: "center", marginTop: "20px" }}>
            <CircularProgress />
          </div>
        ) : (
          <>
            {!caseId && (
              <Autocomplete
                options={cases}
                getOptionLabel={(option) => option.name}
                value={selectedEvidence}
                onChange={(_event, newValue) => {
                  setSelectedEvidence(newValue);
                }}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label="Linked Case"
                    margin="dense"
                    fullWidth
                    required
                  />
                )}
              />
            )}
            <FormControl fullWidth margin="dense">
              <InputLabel id="os-select-label">Source OS</InputLabel>
              <Select
                labelId="os-select-label"
                label="Operating System"
                value={os}
                onChange={(e) => setOs(e.target.value as string)}
              >
                {OS_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <Button
              variant="outlined"
              component="label"
              style={{ marginTop: 16 }}
              color="secondary"
            >
              Select File
              <input
                type="file"
                hidden
                onChange={(e) =>
                  setFile(e.target.files ? e.target.files[0] : null)
                }
              />
            </Button>
            {file && (
              <div style={{ marginTop: 8 }}>Selected File: {file.name}</div>
            )}
            {error && (
              <div style={{ color: "red", marginTop: 16 }}>{error}</div>
            )}
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={evidenceLoading}>
          Cancel
        </Button>
        <Button
          onClick={handleUpload}
          variant="outlined"
          color="error"
          disabled={
            uploadState.uploading ||
            (!selectedEvidence && !caseId) ||
            evidenceLoading
          }
        >
          Upload
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EvidenceCreationDialog;
