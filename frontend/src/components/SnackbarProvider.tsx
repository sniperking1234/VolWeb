import React, {
  createContext,
  useState,
  useContext,
  useEffect,
  ReactNode,
  useMemo,
  useCallback,
} from "react";
import { Snackbar, Alert, AlertColor } from "@mui/material";

interface SnackbarContextValue {
  display_message: (severity: AlertColor, message: string) => void;
}

const SnackbarContext = createContext<SnackbarContextValue | undefined>(
  undefined,
);

export const useSnackbar = (): SnackbarContextValue => {
  const context = useContext(SnackbarContext);
  if (!context) {
    throw new Error("useSnackbar must be used within a SnackbarProvider");
  }
  return context;
};

interface SnackbarProviderProps {
  children: ReactNode;
}

export const SnackbarProvider: React.FC<SnackbarProviderProps> = ({
  children,
}) => {
  const [open, setOpen] = useState<boolean>(false);
  const [severity, setSeverity] = useState<AlertColor>("success");
  const [message, setMessage] = useState<string>("");

  // Memoize the display_message function
  const display_message = useCallback(
    (severity: AlertColor, message: string) => {
      setSeverity(severity);
      setMessage(message);
      setOpen(true);
    },
    [],
  );

  const contextValue = useMemo(() => ({ display_message }), [display_message]);

  useEffect(() => {
    const handler = (e: Event) => {
      const message = (e as CustomEvent<{ message: string }>).detail.message;
      display_message("error", message);
    };
    window.addEventListener("api:forbidden", handler);
    return () => window.removeEventListener("api:forbidden", handler);
  }, [display_message]);

  const handleClose = (
    _event?: React.SyntheticEvent | Event,
    reason?: string,
  ) => {
    if (reason === "clickaway") {
      return;
    }
    setOpen(false);
  };

  return (
    <SnackbarContext.Provider value={contextValue}>
      {children}
      <Snackbar
        open={open}
        autoHideDuration={6000}
        onClose={handleClose}
        anchorOrigin={{ vertical: "bottom", horizontal: "left" }}
      >
        <Alert
          onClose={handleClose}
          severity={severity}
          sx={{ width: "100%" }}
          elevation={6}
          variant="outlined"
        >
          {message}
        </Alert>
      </Snackbar>
    </SnackbarContext.Provider>
  );
};
