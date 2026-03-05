import React, {
  createContext,
  useContext,
  useState,
  useRef,
  useCallback,
  ReactNode,
} from "react";
import {
  Snackbar,
  Box,
  Typography,
  LinearProgress,
  IconButton,
} from "@mui/material";
import { Close as CloseIcon } from "@mui/icons-material";
import axiosInstance from "../utils/axiosInstance";
import { useSnackbar } from "./SnackbarProvider";

interface UploadState {
  uploading: boolean;
  uploadProgress: number | null;
  fileName: string | null;
}

interface EvidenceUploadContextValue {
  uploadState: UploadState;
  startUpload: (params: {
    file: File;
    caseId: number;
    os: string;
  }) => void;
  cancelUpload: () => void;
}

const EvidenceUploadContext = createContext<
  EvidenceUploadContextValue | undefined
>(undefined);

export const useEvidenceUpload = (): EvidenceUploadContextValue => {
  const context = useContext(EvidenceUploadContext);
  if (!context) {
    throw new Error(
      "useEvidenceUpload must be used within an EvidenceUploadProvider",
    );
  }
  return context;
};

const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB

interface EvidenceUploadProviderProps {
  children: ReactNode;
}

export const EvidenceUploadProvider: React.FC<EvidenceUploadProviderProps> = ({
  children,
}) => {
  const { display_message } = useSnackbar();
  const [uploadState, setUploadState] = useState<UploadState>({
    uploading: false,
    uploadProgress: null,
    fileName: null,
  });

  const abortControllerRef = useRef<AbortController | null>(null);

  const cancelUpload = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setUploadState({ uploading: false, uploadProgress: null, fileName: null });
    display_message("warning", "Upload cancelled.");
  }, [display_message]);

  const startUpload = useCallback(
    (params: { file: File; caseId: number; os: string }) => {
      const { file, caseId, os } = params;
      const controller = new AbortController();
      abortControllerRef.current = controller;

      setUploadState({
        uploading: true,
        uploadProgress: 0,
        fileName: file.name,
      });

      const doUpload = async () => {
        try {
          const initiateResponse = await axiosInstance.post(
            `/api/cases/upload/initiate/`,
            {
              filename: file.name,
              case_id: caseId,
              os: os,
            },
            { signal: controller.signal },
          );
          const uploadId = initiateResponse.data.upload_id;

          const chunks: Blob[] = [];
          let currentPointer = 0;
          while (currentPointer < file.size) {
            chunks.push(
              file.slice(currentPointer, currentPointer + CHUNK_SIZE),
            );
            currentPointer += CHUNK_SIZE;
          }

          let uploadedSize = 0;
          for (let index = 0; index < chunks.length; index++) {
            const chunk = chunks[index];
            const partNumber = index + 1;

            const formData = new FormData();
            formData.append(
              "chunk",
              chunk,
              file.name + ".part" + partNumber,
            );
            formData.append("upload_id", uploadId);
            formData.append("part_number", partNumber.toString());
            formData.append("filename", file.name);

            await axiosInstance.post(`/api/cases/upload/chunk/`, formData, {
              signal: controller.signal,
            });

            uploadedSize += chunk.size;
            const percentage = Math.round((uploadedSize / file.size) * 100);
            setUploadState((prev) => ({
              ...prev,
              uploadProgress: percentage,
            }));
          }

          await axiosInstance.post(
            `/api/cases/upload/complete/`,
            { upload_id: uploadId },
            { signal: controller.signal },
          );

          display_message("success", "Evidence created.");
        } catch (err) {
          if (controller.signal.aborted) return;
          console.error("Upload error:", err);
          display_message("error", `Evidence upload failed.`);
        } finally {
          abortControllerRef.current = null;
          setUploadState({
            uploading: false,
            uploadProgress: null,
            fileName: null,
          });
        }
      };

      doUpload();
    },
    [display_message],
  );

  return (
    <EvidenceUploadContext.Provider
      value={{ uploadState, startUpload, cancelUpload }}
    >
      {children}
      <Snackbar
        open={uploadState.uploading}
        anchorOrigin={{ vertical: "bottom", horizontal: "left" }}
        sx={{ left: { xs: 72, sm: 80 } }}
      >
        <Box
          sx={{
            bgcolor: "background.paper",
            borderRadius: 1,
            boxShadow: 3,
            p: 2,
            minWidth: 300,
          }}
        >
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              mb: 1,
            }}
          >
            <Typography variant="body2">
              Uploading: {uploadState.fileName}
            </Typography>
            <IconButton size="small" onClick={cancelUpload}>
              <CloseIcon fontSize="small" />
            </IconButton>
          </Box>
          <LinearProgress
            variant="determinate"
            value={uploadState.uploadProgress || 0}
          />
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ mt: 0.5, display: "block" }}
          >
            {uploadState.uploadProgress}%
          </Typography>
        </Box>
      </Snackbar>
    </EvidenceUploadContext.Provider>
  );
};
