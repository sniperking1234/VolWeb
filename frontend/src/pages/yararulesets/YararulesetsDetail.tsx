import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { YaraRuleSet } from "../../types";
import axiosInstance from "../../utils/axiosInstance";
import {
  Typography,
  CircularProgress,
  Card,
  CardContent,
  Divider,
  Box,
} from "@mui/material";
import Grid from "@mui/material/Grid";
import YaraRuleList from "../../components/Lists/YaraRuleList";
import { useSnackbar } from "../../components/SnackbarProvider";
const RulesetDetail: React.FC = () => {
  const { display_message } = useSnackbar();

  const { id } = useParams<{ id: string }>();
  const [rulesetDetail, setRulesetDetail] = useState<YaraRuleSet | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchRulesetDetail = async () => {
      try {
        const response = await axiosInstance.get(`/api/yararulesets/${id}/`);
        setRulesetDetail(response.data);
        setLoading(false);
      } catch (error) {
        display_message("error", `An error fetching ruleset details: ${error}`);
        console.error("Error fetching ruleset details", error);
      }
    };

    fetchRulesetDetail();
  }, [id, display_message]);

  if (loading) {
    return <CircularProgress />;
  }

  return (
    rulesetDetail && (
      <Grid spacing={2} container>
        <Grid size={12}>
          <Card variant="outlined" sx={{ marginBottom: 2 }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="h5" component="div">
                    {rulesetDetail.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {rulesetDetail.description}
                  </Typography>
                </Box>
                <Box sx={{ textAlign: 'right' }}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Rules: {rulesetDetail.rules ? rulesetDetail.rules.length : 0}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={12}>
          <Typography variant="h5" component="div" sx={{ marginBottom: 2 }}>
            Linked rules
          </Typography>
          <Divider sx={{ marginBottom: 2 }} />
          <YaraRuleList yararuleset={rulesetDetail} />
        </Grid>
      </Grid>
    )
  );
};

export default RulesetDetail;