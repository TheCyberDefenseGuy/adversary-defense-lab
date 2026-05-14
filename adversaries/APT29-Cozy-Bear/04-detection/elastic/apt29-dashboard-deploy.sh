#!/bin/bash
# =============================================================================
# apt29-dashboard-deploy.sh — APT29 Kibana Dashboard Deploy
# Adversary Defense Lab — APT29 Cozy Bear Detection
#
# Cria um dashboard completo no Kibana com 5 visualizações
# via Saved Objects API. Todo o processo é feito via CLI
# sem necessidade de interagir com a interface gráfica do Kibana.
#
# Visualizações criadas:
#   1. Gauge     — TTPs Detectados (unique count de regras)
#   2. Bar       — Alertas por TTP (horizontal bar chart)
#   3. Timeline  — Alertas ao longo do tempo por severity
#   4. Treemap   — MITRE Heatmap proporcional por TTP
#   5. Datatable — Últimos Alertas com rule + severity + count
#
# Uso:
#   chmod +x apt29-dashboard-deploy.sh
#   ./apt29-dashboard-deploy.sh
#   ./apt29-dashboard-deploy.sh --delete    # apaga e recria
#
# Pré-requisitos:
#   curl, python3
# =============================================================================

KIBANA="http://192.168.10.20:5601"
USER="elastic"
PASS="tg8oCneGV2pgtFWxHbOD"
AUTH="${USER}:${PASS}"
DV_ID="apt29-alerts-dataview"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✅ $1${NC}"; }
fail() { echo -e "  ${RED}❌ $1${NC}"; }
info() { echo -e "  ${BLUE}→  $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; }

save_object() {
  local TYPE=$1; local ID=$2; local BODY=$3
  STATUS=$(curl -sk -o /tmp/kbn_resp.json -w "%{http_code}" \
    -X POST "${KIBANA}/api/saved_objects/${TYPE}/${ID}?overwrite=true" \
    -u "${AUTH}" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    -d "${BODY}")
  if [[ "$STATUS" == "200" || "$STATUS" == "201" ]]; then
    ok "${TYPE}/${ID}"
  else
    fail "${TYPE}/${ID} → HTTP ${STATUS}"
    python3 -c "import json; d=json.load(open('/tmp/kbn_resp.json')); print('  ',d.get('message','?'))" 2>/dev/null
  fi
}

delete_object() {
  local TYPE=$1; local ID=$2
  curl -sk -o /dev/null -X DELETE "${KIBANA}/api/saved_objects/${TYPE}/${ID}" \
    -u "${AUTH}" -H "kbn-xsrf: true"
  echo -e "  ${YELLOW}🗑  Apagado ${TYPE}/${ID}${NC}"
}

# ─── Delete mode ──────────────────────────────────────────────────────────────
if [[ "$1" == "--delete" ]]; then
  echo -e "\n${RED}🗑  A apagar dashboard APT29...${NC}"
  delete_object dashboard "apt29-main-dashboard"
  for ID in apt29-viz-gauge apt29-viz-bar apt29-viz-timeline apt29-viz-treemap apt29-viz-table; do
    delete_object lens "$ID"
  done
  curl -sk -o /dev/null -X DELETE "${KIBANA}/api/data_views/data_view/${DV_ID}" \
    -u "${AUTH}" -H "kbn-xsrf: true"
  echo -e "  ${YELLOW}🗑  Apagado data_view/${DV_ID}${NC}"
  echo -e "\n${GREEN}Feito. Corre o script sem --delete para recriar.${NC}\n"
  exit 0
fi

# ─── Banner ───────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  APT29 Dashboard Deploy — $(date '+%Y-%m-%d %H:%M')${NC}"
echo -e "${BLUE}  Kibana: ${KIBANA}${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════${NC}\n"

# ─── Verificar ligação ────────────────────────────────────────────────────────
info "A verificar ligação ao Kibana..."
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" -u "${AUTH}" "${KIBANA}/api/status")
if [[ "$STATUS" != "200" ]]; then
  fail "Não consigo ligar ao Kibana (HTTP ${STATUS})"
  exit 1
fi
ok "Kibana acessível"

# ─── Data View ────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}🔧 Data View para alertas SIEM...${NC}"
curl -sk -o /dev/null -X DELETE "${KIBANA}/api/data_views/data_view/${DV_ID}" \
  -u "${AUTH}" -H "kbn-xsrf: true"
DV_STATUS=$(curl -sk -o /tmp/kbn_dv.json -w "%{http_code}" \
  -X POST "${KIBANA}/api/data_views/data_view" \
  -u "${AUTH}" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d "{\"data_view\":{\"id\":\"${DV_ID}\",\"title\":\".internal.alerts-security.alerts-default-000001\",\"name\":\"APT29 Security Alerts\",\"timeFieldName\":\"@timestamp\"}}")
[[ "$DV_STATUS" == "200" || "$DV_STATUS" == "201" ]] && ok "Data View: APT29 Security Alerts" || fail "Data View HTTP ${DV_STATUS}"

# ─── VIZ 1: Gauge — TTPs Detectados ──────────────────────────────────────────
echo -e "\n${YELLOW}📊 VIZ 1/5 — Gauge: TTPs Detectados${NC}"
save_object lens "apt29-viz-gauge" '{
  "attributes": {
    "title": "APT29 — TTPs Detectados",
    "visualizationType": "lnsMetric",
    "state": {
      "datasourceStates": {
        "formBased": {
          "layers": {
            "layer1": {
              "columnOrder": ["col_unique"],
              "columns": {
                "col_unique": {
                  "label": "TTPs Detectados",
                  "dataType": "number",
                  "operationType": "unique_count",
                  "sourceField": "kibana.alert.rule.name",
                  "isBucketed": false
                }
              },
              "indexPatternId": "apt29-alerts-dataview"
            }
          }
        }
      },
      "filters": [],
      "query": {"language": "kuery", "query": ""},
      "visualization": {
        "layerId": "layer1",
        "layerType": "data",
        "metricAccessor": "col_unique",
        "color": "#00BFB3"
      }
    }
  },
  "references": [{"id": "apt29-alerts-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
}'

# ─── VIZ 2: Bar — Alertas por TTP ─────────────────────────────────────────────
echo -e "\n${YELLOW}📊 VIZ 2/5 — Bar: Alertas por TTP${NC}"
save_object lens "apt29-viz-bar" '{
  "attributes": {
    "title": "APT29 — Alertas por TTP",
    "visualizationType": "lnsXY",
    "state": {
      "datasourceStates": {
        "formBased": {
          "layers": {
            "layer1": {
              "columnOrder": ["col_rule", "col_count"],
              "columns": {
                "col_rule": {
                  "label": "Regra",
                  "dataType": "string",
                  "operationType": "terms",
                  "sourceField": "kibana.alert.rule.name",
                  "isBucketed": true,
                  "params": {"size": 12, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc"}
                },
                "col_count": {
                  "label": "Alertas",
                  "dataType": "number",
                  "operationType": "count",
                  "isBucketed": false,
                  "sourceField": "___records___"
                }
              },
              "indexPatternId": "apt29-alerts-dataview"
            }
          }
        }
      },
      "filters": [],
      "query": {"language": "kuery", "query": ""},
      "visualization": {
        "preferredSeriesType": "bar_horizontal",
        "legend": {"isVisible": true, "position": "right"},
        "valueLabels": "show",
        "layers": [{"layerId": "layer1", "layerType": "data", "seriesType": "bar_horizontal", "xAccessor": "col_rule", "accessors": ["col_count"]}]
      }
    }
  },
  "references": [{"id": "apt29-alerts-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
}'

# ─── VIZ 3: Timeline — Alertas ao longo do tempo ──────────────────────────────
echo -e "\n${YELLOW}📊 VIZ 3/5 — Timeline: Alertas ao longo do tempo${NC}"
save_object lens "apt29-viz-timeline" '{
  "attributes": {
    "title": "APT29 — Timeline de Alertas",
    "visualizationType": "lnsXY",
    "state": {
      "datasourceStates": {
        "formBased": {
          "layers": {
            "layer1": {
              "columnOrder": ["col_time", "col_severity", "col_count"],
              "columns": {
                "col_time": {
                  "label": "Timestamp",
                  "dataType": "date",
                  "operationType": "date_histogram",
                  "sourceField": "@timestamp",
                  "isBucketed": true,
                  "params": {"interval": "auto"}
                },
                "col_severity": {
                  "label": "Severity",
                  "dataType": "string",
                  "operationType": "terms",
                  "sourceField": "kibana.alert.severity",
                  "isBucketed": true,
                  "params": {"size": 5, "orderBy": {"type": "alphabetical"}, "orderDirection": "asc"}
                },
                "col_count": {
                  "label": "Alertas",
                  "dataType": "number",
                  "operationType": "count",
                  "isBucketed": false,
                  "sourceField": "___records___"
                }
              },
              "indexPatternId": "apt29-alerts-dataview"
            }
          }
        }
      },
      "filters": [],
      "query": {"language": "kuery", "query": ""},
      "visualization": {
        "preferredSeriesType": "area",
        "legend": {"isVisible": true, "position": "right"},
        "layers": [{"layerId": "layer1", "layerType": "data", "seriesType": "area", "xAccessor": "col_time", "splitAccessor": "col_severity", "accessors": ["col_count"]}]
      }
    }
  },
  "references": [{"id": "apt29-alerts-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
}'

# ─── VIZ 4: Treemap — MITRE Heatmap ───────────────────────────────────────────
echo -e "\n${YELLOW}📊 VIZ 4/5 — Treemap: MITRE Heatmap${NC}"
save_object lens "apt29-viz-treemap" '{
  "attributes": {
    "title": "APT29 — MITRE Heatmap",
    "visualizationType": "lnsPie",
    "state": {
      "datasourceStates": {
        "formBased": {
          "layers": {
            "layer1": {
              "columnOrder": ["col_rule", "col_count"],
              "columns": {
                "col_rule": {
                  "label": "Regra",
                  "dataType": "string",
                  "operationType": "terms",
                  "sourceField": "kibana.alert.rule.name",
                  "isBucketed": true,
                  "params": {"size": 12, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc"}
                },
                "col_count": {
                  "label": "Alertas",
                  "dataType": "number",
                  "operationType": "count",
                  "isBucketed": false,
                  "sourceField": "___records___"
                }
              },
              "indexPatternId": "apt29-alerts-dataview"
            }
          }
        }
      },
      "filters": [],
      "query": {"language": "kuery", "query": ""},
      "visualization": {
        "shape": "treemap",
        "layers": [{
          "layerId": "layer1",
          "layerType": "data",
          "primaryGroups": ["col_rule"],
          "metrics": ["col_count"],
          "numberDisplay": "value",
          "categoryDisplay": "default",
          "legendDisplay": "default",
          "nestedLegend": false
        }]
      }
    }
  },
  "references": [{"id": "apt29-alerts-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
}'

# ─── VIZ 5: Datatable — Últimos Alertas ───────────────────────────────────────
echo -e "\n${YELLOW}📊 VIZ 5/5 — Tabela: Últimos Alertas${NC}"
save_object lens "apt29-viz-table" '{
  "attributes": {
    "title": "APT29 — Ultimos Alertas",
    "visualizationType": "lnsDatatable",
    "state": {
      "datasourceStates": {
        "formBased": {
          "layers": {
            "layer1": {
              "columnOrder": ["col_rule", "col_severity", "col_count"],
              "columns": {
                "col_rule": {
                  "label": "Regra (TTP)",
                  "dataType": "string",
                  "operationType": "terms",
                  "sourceField": "kibana.alert.rule.name",
                  "isBucketed": true,
                  "params": {"size": 12, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc"}
                },
                "col_severity": {
                  "label": "Severity",
                  "dataType": "string",
                  "operationType": "terms",
                  "sourceField": "kibana.alert.severity",
                  "isBucketed": true,
                  "params": {"size": 5, "orderBy": {"type": "alphabetical"}, "orderDirection": "asc"}
                },
                "col_count": {
                  "label": "Total Alertas",
                  "dataType": "number",
                  "operationType": "count",
                  "isBucketed": false,
                  "sourceField": "___records___"
                }
              },
              "indexPatternId": "apt29-alerts-dataview"
            }
          }
        }
      },
      "filters": [],
      "query": {"language": "kuery", "query": ""},
      "visualization": {
        "layerId": "layer1",
        "layerType": "data",
        "columns": [{"columnId": "col_rule"}, {"columnId": "col_severity"}, {"columnId": "col_count"}],
        "sorting": {"columnId": "col_count", "direction": "desc"}
      }
    }
  },
  "references": [{"id": "apt29-alerts-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
}'

# ─── Dashboard principal ───────────────────────────────────────────────────────
echo -e "\n${YELLOW}📋 Dashboard principal...${NC}"
save_object dashboard "apt29-main-dashboard" '{
  "attributes": {
    "title": "APT29 Emulation — SOC Dashboard",
    "description": "Dashboard de deteccao APT29 — 12 TTPs MITRE ATT&CK | Adversary Defense Lab",
    "panelsJSON": "[{\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":0,\"w\":12,\"h\":8,\"i\":\"p1\"},\"panelIndex\":\"p1\",\"embeddableConfig\":{\"savedObjectId\":\"apt29-viz-gauge\",\"enhancements\":{}},\"title\":\"TTPs Detectados\"},{\"type\":\"lens\",\"gridData\":{\"x\":12,\"y\":0,\"w\":36,\"h\":15,\"i\":\"p2\"},\"panelIndex\":\"p2\",\"embeddableConfig\":{\"savedObjectId\":\"apt29-viz-bar\",\"enhancements\":{}},\"title\":\"Alertas por TTP\"},{\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":15,\"w\":48,\"h\":15,\"i\":\"p3\"},\"panelIndex\":\"p3\",\"embeddableConfig\":{\"savedObjectId\":\"apt29-viz-timeline\",\"enhancements\":{}},\"title\":\"Timeline de Alertas\"},{\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":30,\"w\":24,\"h\":15,\"i\":\"p4\"},\"panelIndex\":\"p4\",\"embeddableConfig\":{\"savedObjectId\":\"apt29-viz-treemap\",\"enhancements\":{}},\"title\":\"MITRE Heatmap\"},{\"type\":\"lens\",\"gridData\":{\"x\":24,\"y\":30,\"w\":24,\"h\":15,\"i\":\"p5\"},\"panelIndex\":\"p5\",\"embeddableConfig\":{\"savedObjectId\":\"apt29-viz-table\",\"enhancements\":{}},\"title\":\"Ultimos Alertas\"}]",
    "optionsJSON": "{\"useMargins\":true,\"syncColors\":true,\"hidePanelTitles\":false}",
    "timeRestore": false,
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"\"},\"filter\":[]}"
    }
  }
}'

# ─── Resultado final ───────────────────────────────────────────────────────────
echo -e "\n${BLUE}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Dashboard APT29 criado com sucesso!${NC}"
echo -e ""
echo -e "  🔗 ${KIBANA}/app/dashboards"
echo -e "  🔍 Procura: 'APT29 Emulation — SOC Dashboard'"
echo -e "  ⏱  Time range: Last 7 days"
echo -e ""
echo -e "  Para recriar do zero:"
echo -e "  ${YELLOW}./apt29-dashboard-deploy.sh --delete && ./apt29-dashboard-deploy.sh${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════${NC}\n"
