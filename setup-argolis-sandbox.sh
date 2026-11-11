#!/usr/bin/env bash
# ==============================================================================
# Intuitive Surgical — HIPAA V4 Signed URL + Per-Hospital CMEK Sandbox Wizard
# ==============================================================================
# Idempotent setup & end-to-end verification script for Google Cloud Argolis.
# Any teammate can run this script against their own Argolis organization to
# replicate and validate the complete HIPAA surgical video download architecture:
#
#   1. Shared GCS Bucket (UBLA + PAP) with Per-Hospital CMEK Keys (Stanford vs Mayo)
#   2. Keyless V4 Signed URLs via IAM signBlob (5-min TTL + Cache-Control: no-store)
#   3. Tamper-Proof User Attribution via 4 x-goog-custom-audit-* Signed Query Tags
#   4. Instant Per-Hospital KMS Kill Switch (Crypto-Shredding Active Signed URLs)
#   5. Dual Audit Trail (GCS DATA_READ + KMS Decrypt) -> 6-Year Cloud Logging Vault
#
# Usage:
#   ./setup-argolis-sandbox.sh              # Interactive build + E2E test wizard
#   ./setup-argolis-sandbox.sh --auto       # Non-interactive build + E2E test
#   ./setup-argolis-sandbox.sh --test-only  # Re-run unit + live E2E verification
#   ./setup-argolis-sandbox.sh --portal     # Launch local browser download UI (:8080)
#   ./setup-argolis-sandbox.sh --destroy    # Tear down deployed PoC project via Terraform
#   ./setup-argolis-sandbox.sh --sterilize  # Strip local state/IDs before sharing repo
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CONFIG_FILE="${SCRIPT_DIR}/.argolis-config.env"
TF_DIR="${SCRIPT_DIR}/terraform"
TFVARS_FILE="${TF_DIR}/terraform.tfvars"
TFVARS_TEMPLATE="${TF_DIR}/terraform.tfvars.template"
VENV_DIR="${SCRIPT_DIR}/.venv"

# ------------------------------------------------------------------------------
# Terminal Colors & Formatting Helpers
# ------------------------------------------------------------------------------
BOLD="\033[1m"
DIM="\033[2m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

banner() {
  echo ""
  echo -e "${BOLD}${BLUE}================================================================================${RESET}"
  echo -e "${BOLD}${CYAN}  $1${RESET}"
  echo -e "${BOLD}${BLUE}================================================================================${RESET}"
}

info()    { echo -e "${CYAN}ℹ${RESET}  $1"; }
success() { echo -e "${GREEN}✔${RESET}  $1"; }
warn()    { echo -e "${YELLOW}⚠${RESET}  $1"; }
error()   { echo -e "${RED}✖${RESET}  $1"; }

on_error() {
  local exit_code=$?
  local line_no=$1
  echo ""
  echo -e "${BOLD}${RED}================================================================================${RESET}"
  echo -e "${BOLD}${RED}  ❌ SETUP INTERRUPTED (Exit Code ${exit_code} at Line ${line_no})${RESET}"
  echo -e "${BOLD}${RED}================================================================================${RESET}"
  echo -e "👉 ${BOLD}How to recover:${RESET}"
  echo -e "   1. Copy the error output above and ask ${BOLD}Antigravity${RESET}:"
  echo -e "      ${YELLOW}\"Fix this error from setup-argolis-sandbox.sh and explain what caused it.\"${RESET}"
  echo -e "   2. Once resolved, simply re-run this script (it is 100% idempotent):"
  echo -e "      ${GREEN}./setup-argolis-sandbox.sh${RESET}"
  echo ""
  exit "$exit_code"
}
trap 'on_error $LINENO' ERR

# Wrap binary downloads (terraform init / pip install) with gpkg when running on
# Google Corp macOS (Santa Lockdown) so downloaded plugins/wheels are allowlisted.
export PATH="/usr/local/bin:/opt/homebrew/bin:${PATH}"

for gcloud_cand_dir in \
  "${HOME}/google-cloud-sdk/bin" \
  "/usr/local/google-cloud-sdk/bin" \
  "/Applications/Google Cloud SDK/bin" \
  "/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin" \
  "/opt/homebrew/share/google-cloud-sdk/bin"; do
  if [[ -x "${gcloud_cand_dir}/gcloud" ]]; then
    export PATH="${gcloud_cand_dir}:${PATH}"
    break
  fi
done

# Discover a Santa-allowlisted Python >= 3.10 interpreter (prioritizing GoogleCorpSupport Python on gMac
# so Homebrew Python blocked by Santa or macOS system Python 3.9 never breaks gcloud or venv).
PYTHON_BIN=""
for py_cand in \
  "/Library/GoogleCorpSupport/Python/3.13/bin/python3" \
  "/Library/GoogleCorpSupport/Python/3.12/bin/python3" \
  "/Library/GoogleCorpSupport/Python/3.11/bin/python3" \
  "/Library/GoogleCorpSupport/Python/3.10/bin/python3" \
  "${HOME}/google-cloud-sdk/platform/bundledpythonunix/bin/python3" \
  "$(command -v python3 2>/dev/null || true)" \
  "/usr/bin/python3"; do
  if [[ -n "$py_cand" ]] && [[ -x "$py_cand" ]]; then
    if "$py_cand" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
      PYTHON_BIN="$py_cand"
      break
    fi
  fi
done
if [[ -z "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3 2>/dev/null || echo /usr/bin/python3)"
fi
export CLOUDSDK_PYTHON="${CLOUDSDK_PYTHON:-$PYTHON_BIN}"

run_with_gpkg() {
  if command -v gpkg >/dev/null 2>&1; then
    gpkg "$@"
  else
    "$@"
  fi
}

# ------------------------------------------------------------------------------
# Parse CLI Flags
# ------------------------------------------------------------------------------
MODE="wizard"
AUTO_APPROVE="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto|-y)
      AUTO_APPROVE="true"
      shift
      ;;
    --test-only)
      MODE="test-only"
      shift
      ;;
    --portal)
      MODE="portal"
      shift
      ;;
    --destroy)
      MODE="destroy"
      shift
      ;;
    --sterilize)
      MODE="sterilize"
      shift
      ;;
    --help|-h)
      sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      error "Unknown option: $1 (run ./setup-argolis-sandbox.sh --help)"
      exit 1
      ;;
  esac
done

prompt_val() {
  local prompt_text="$1"
  local default_val="$2"
  local var_name="$3"
  if [[ "$AUTO_APPROVE" == "true" ]]; then
    printf -v "$var_name" '%s' "$default_val"
  else
    local input_val=""
    read -r -p "${prompt_text} [${default_val}]: " input_val
    printf -v "$var_name" '%s' "${input_val:-$default_val}"
  fi
}

ensure_python_venv() {
  if [[ -x "${VENV_DIR}/bin/python3" ]]; then
    if ! "${VENV_DIR}/bin/python3" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
      info "Upgrading Python virtual environment to ${PYTHON_BIN}..."
      rm -rf "$VENV_DIR"
    fi
  fi
  if [[ ! -x "${VENV_DIR}/bin/python3" ]]; then
    info "Creating Python virtual environment in ${VENV_DIR} using ${PYTHON_BIN}..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
  fi
  info "Ensuring Google Cloud Python SDK dependencies are installed..."
  run_with_gpkg "${VENV_DIR}/bin/pip" install --upgrade pip -q
  run_with_gpkg "${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/scripts/requirements.txt" -q
  success "Python test environment ready (${VENV_DIR})."
}

# Load cached configuration from prior runs if present
if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

save_config() {
  cat > "$CONFIG_FILE" <<EOF
# Auto-generated by setup-argolis-sandbox.sh — safe to re-run (gitignored)
ARGOLIS_USER="${ARGOLIS_USER:-}"
ARGOLIS_DOMAIN="${ARGOLIS_DOMAIN:-}"
ARGOLIS_ORG_ID="${ARGOLIS_ORG_ID:-}"
ARGOLIS_BILLING_ACCOUNT="${ARGOLIS_BILLING_ACCOUNT:-}"
ARGOLIS_FOLDER_ID="${ARGOLIS_FOLDER_ID:-}"
ARGOLIS_QUOTA_PROJECT="${ARGOLIS_QUOTA_PROJECT:-}"
ARGOLIS_REGION="${ARGOLIS_REGION:-us-central1}"
ARGOLIS_PROJECT_PREFIX="${ARGOLIS_PROJECT_PREFIX:-isrg-hipaa-vid}"
EOF
}

# ------------------------------------------------------------------------------
# Shortcut Modes (--sterilize, --portal, --destroy, --test-only)
# ------------------------------------------------------------------------------
if [[ "$MODE" == "sterilize" ]]; then
  banner "Sterilizing Repository for Sharing"
  if [[ -f "${TF_DIR}/terraform.tfstate" ]] && grep -q '"resources": \[' "${TF_DIR}/terraform.tfstate" 2>/dev/null; then
    warn "Active terraform.tfstate detected! Run './setup-argolis-sandbox.sh --destroy' first if you want to delete live cloud resources before sterilizing."
    read -r -p "Proceed with removing local state/config files anyway? [y/N]: " CONFIRM_STERILIZE
    if [[ ! "$CONFIRM_STERILIZE" =~ ^[Yy]$ ]]; then
      info "Aborted sterilize."
      exit 0
    fi
  fi
  rm -rf "$CONFIG_FILE" "$TFVARS_FILE" "$VENV_DIR" \
    "${TF_DIR}/.terraform" "${TF_DIR}/tfplan" \
    "${TF_DIR}/terraform.tfstate" "${TF_DIR}/terraform.tfstate.backup" \
    "${SCRIPT_DIR}/scripts/__pycache__"
  success "Removed .argolis-config.env, terraform.tfvars, .terraform, state files, and .venv."
  success "This folder is now 100% clean and ready to zip or push to Git for teammates!"
  exit 0
fi

if [[ "$MODE" == "portal" ]]; then
  banner "Launching Local Hospital Browser Download Portal (http://127.0.0.1:8080)"
  ensure_python_venv
  exec "${VENV_DIR}/bin/python3" "${SCRIPT_DIR}/scripts/portal_demo.py"
fi

if [[ "$MODE" == "destroy" ]]; then
  banner "Tearing Down Intuitive HIPAA PoC Project in Argolis"
  if [[ ! -f "$TFVARS_FILE" ]]; then
    error "No ${TFVARS_FILE} found. Nothing to destroy."
    exit 1
  fi
  (
    cd "$TF_DIR"
    if [[ "$AUTO_APPROVE" == "true" ]]; then
      terraform destroy -auto-approve
    else
      terraform destroy
    fi
  )
  success "Argolis HIPAA PoC project and resources cleanly destroyed."
  exit 0
fi

if [[ "$MODE" == "test-only" ]]; then
  banner "Running Offline Terraform Unit Tests + Live 6-Stage Argolis Verification"
  (
    cd "$TF_DIR"
    run_with_gpkg terraform init -input=false >/dev/null
    terraform test
  )
  ensure_python_venv
  "${VENV_DIR}/bin/python3" "${SCRIPT_DIR}/scripts/e2e_verify.py"
  exit 0
fi

# ==============================================================================
# STEP 1/7: Pre-Flight Check & Argolis Admin Authentication
# ==============================================================================
banner "STEP 1/7: Pre-Flight Check & Argolis Admin Authentication"

echo -e "${BOLD}Recommended Platform & Account:${RESET}"
echo -e "  • ${BOLD}Platform:${RESET} Google Cloud ${BOLD}Argolis${RESET} environment"
echo -e "  • ${BOLD}Account:${RESET}  ${GREEN}admin@<your-domain>.altostrat.com${RESET}"
echo -e "    ${DIM}(Why admin@? On Argolis, ONLY the admin@ persona has Billing Account permissions${RESET}"
echo -e "    ${DIM}and Org IAM admin rights by default to create folders and link project billing.)${RESET}"
echo ""

for cmd in gcloud terraform; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    error "'${cmd}' CLI is not installed or not on PATH. Please install it and re-run."
    exit 1
  fi
done
if [[ ! -x "$PYTHON_BIN" ]]; then
  error "No working Python 3 interpreter found. Please install Python >= 3.10 and re-run."
  exit 1
fi

TF_VERSION="$(terraform version -json 2>/dev/null | grep -o '"terraform_version":[[:space:]]*"[^"]*"' | cut -d'"' -f4 || terraform version | head -n1)"
PY_VERSION="$("$PYTHON_BIN" --version 2>&1)"
GCLOUD_BIN_PATH="$(command -v gcloud)"
success "Found gcloud (${GCLOUD_BIN_PATH}), Terraform (${TF_VERSION}), and ${PY_VERSION} (${PYTHON_BIN})"

CURRENT_ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
echo ""
info "Current active gcloud account: ${BOLD}${CURRENT_ACCOUNT:-<none>}${RESET}"

if [[ -z "$CURRENT_ACCOUNT" ]] || [[ "$CURRENT_ACCOUNT" != admin@* ]]; then
  warn "Your active gcloud account (${CURRENT_ACCOUNT:-none}) does not start with 'admin@'."
  echo -e "   We strongly recommend authenticating as ${BOLD}admin@<your-domain>.altostrat.com${RESET}."
fi

# Proactively verify non-interactive token validity for both gcloud CLI & ADC
GCLOUD_TOKEN_OK="true"
ADC_TOKEN_OK="true"
if ! gcloud organizations list --limit=1 --quiet </dev/null >/dev/null 2>&1; then
  GCLOUD_TOKEN_OK="false"
fi
if ! gcloud auth application-default print-access-token --quiet </dev/null >/dev/null 2>&1; then
  ADC_TOKEN_OK="false"
fi

if [[ "$GCLOUD_TOKEN_OK" == "false" ]] || [[ "$ADC_TOKEN_OK" == "false" ]]; then
  warn "Expired or missing credentials detected (gcloud=${GCLOUD_TOKEN_OK}, ADC=${ADC_TOKEN_OK}). Reauthentication required."
  if [[ "$AUTO_APPROVE" == "true" ]]; then
    error "Cannot complete interactive Workspace ReAuth in --auto mode. Run:"
    echo -e "   ${GREEN}gcloud auth login && gcloud auth application-default login${RESET}"
    exit 1
  fi
  LOGIN_HINT="${ARGOLIS_USER:-$CURRENT_ACCOUNT}"
  if [[ "$LOGIN_HINT" == admin@* ]]; then
    info "Launching 'gcloud auth login ${LOGIN_HINT}'..."
    gcloud auth login "$LOGIN_HINT"
  else
    info "Launching 'gcloud auth login' (log in as admin@<your-domain>.altostrat.com)..."
    gcloud auth login
  fi
  info "Launching 'gcloud auth application-default login' (use the SAME admin@ account)..."
  gcloud auth application-default login
  CURRENT_ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
elif [[ "$AUTO_APPROVE" == "false" ]]; then
  read -r -p "Active credentials are valid. Re-run 'gcloud auth login' anyway? [y/N]: " DO_LOGIN
  if [[ "$DO_LOGIN" =~ ^[Yy]$ ]]; then
    gcloud auth login
    gcloud auth application-default login
    CURRENT_ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
  fi
fi

if [[ -z "$CURRENT_ACCOUNT" ]]; then
  error "No active gcloud account found. Authenticate with 'gcloud auth login' and re-run."
  exit 1
fi

ARGOLIS_USER="$CURRENT_ACCOUNT"
DETECTED_DOMAIN="${ARGOLIS_USER#*@}"
ARGOLIS_DOMAIN="${ARGOLIS_DOMAIN:-$DETECTED_DOMAIN}"

prompt_val "Confirm your Argolis Cloud Identity domain" "$ARGOLIS_DOMAIN" ARGOLIS_DOMAIN
success "Using Argolis User: ${BOLD}${ARGOLIS_USER}${RESET} | Domain: ${BOLD}${ARGOLIS_DOMAIN}${RESET}"

info "Looking up Organization ID for ${ARGOLIS_DOMAIN}..."
DETECTED_ORG_ID="$(gcloud organizations list --filter="displayName:${ARGOLIS_DOMAIN}" --format="value(ID)" </dev/null 2>/dev/null | head -n 1 || true)"
if [[ -z "$DETECTED_ORG_ID" ]]; then
  DETECTED_ORG_ID="$(gcloud organizations list --format="value(ID)" </dev/null 2>/dev/null | head -n 1 || true)"
fi
ARGOLIS_ORG_ID="${ARGOLIS_ORG_ID:-$DETECTED_ORG_ID}"

echo ""
gcloud organizations list </dev/null 2>/dev/null || true
echo ""
prompt_val "Confirm your Argolis Organization ID" "$ARGOLIS_ORG_ID" ARGOLIS_ORG_ID
if [[ -z "$ARGOLIS_ORG_ID" ]]; then
  error "Organization ID is required."
  exit 1
fi
save_config
success "Using Organization ID: ${BOLD}${ARGOLIS_ORG_ID}${RESET}"

# ==============================================================================
# STEP 2/7: Billing Account, 'intuitive-hipaa-sandbox' Folder & Quota Project
# ==============================================================================
banner "STEP 2/7: Billing Account, Sandbox Folder & Caller Quota Project"

info "Listing open Billing Accounts accessible to ${ARGOLIS_USER}..."
DETECTED_BILLING="$(gcloud billing accounts list --filter="open=true" --format="value(ACCOUNT_ID)" </dev/null 2>/dev/null | head -n 1 || true)"
ARGOLIS_BILLING_ACCOUNT="${ARGOLIS_BILLING_ACCOUNT:-$DETECTED_BILLING}"

echo ""
gcloud billing accounts list --filter="open=true" </dev/null 2>/dev/null || true
echo ""
if [[ -z "$ARGOLIS_BILLING_ACCOUNT" ]]; then
  warn "No open billing account auto-detected. Ensure you logged in as admin@<domain>.altostrat.com!"
fi
prompt_val "Confirm your Argolis Billing Account ID (XXXXXX-XXXXXX-XXXXXX)" "$ARGOLIS_BILLING_ACCOUNT" ARGOLIS_BILLING_ACCOUNT
if [[ -z "$ARGOLIS_BILLING_ACCOUNT" ]]; then
  error "Billing Account ID is required."
  exit 1
fi
save_config
success "Using Billing Account ID: ${BOLD}${ARGOLIS_BILLING_ACCOUNT}${RESET}"

# Ensure Org-level bootstrap roles on admin@
ORG_ROLES=(
  "roles/resourcemanager.organizationAdmin"
  "roles/resourcemanager.folderAdmin"
  "roles/resourcemanager.projectCreator"
  "roles/orgpolicy.policyAdmin"
)

echo ""
info "Ensuring ${ARGOLIS_USER} has required Organization-level roles on ${ARGOLIS_ORG_ID}..."
for role in "${ORG_ROLES[@]}"; do
  gcloud organizations add-iam-policy-binding "$ARGOLIS_ORG_ID" \
    --member="user:${ARGOLIS_USER}" \
    --role="$role" \
    --condition=None \
    --quiet </dev/null >/dev/null
done
success "Verified Organization-level IAM roles for ${ARGOLIS_USER}."

# Create or reuse 'intuitive-hipaa-sandbox' folder under Org root
SANDBOX_FOLDER_NAME="intuitive-hipaa-sandbox"
echo ""
info "Checking for sandbox folder ${BOLD}'${SANDBOX_FOLDER_NAME}'${RESET} under organizations/${ARGOLIS_ORG_ID}..."
EXISTING_FOLDER="$(gcloud resource-manager folders list \
  --organization="$ARGOLIS_ORG_ID" \
  --filter="displayName='${SANDBOX_FOLDER_NAME}' AND lifecycleState='ACTIVE'" \
  --format="value(name)" </dev/null 2>/dev/null | head -n 1 || true)"

if [[ -n "$EXISTING_FOLDER" ]]; then
  ARGOLIS_FOLDER_ID="${EXISTING_FOLDER#folders/}"
  success "Reusing active '${SANDBOX_FOLDER_NAME}' folder: ${BOLD}folders/${ARGOLIS_FOLDER_ID}${RESET}"
else
  info "Creating folder '${SANDBOX_FOLDER_NAME}' under organizations/${ARGOLIS_ORG_ID}..."
  CREATED_FOLDER="$(gcloud resource-manager folders create \
    --display-name="${SANDBOX_FOLDER_NAME}" \
    --organization="$ARGOLIS_ORG_ID" \
    --format="value(name)" </dev/null)"
  ARGOLIS_FOLDER_ID="${CREATED_FOLDER#folders/}"
  success "Created '${SANDBOX_FOLDER_NAME}' folder: ${BOLD}folders/${ARGOLIS_FOLDER_ID}${RESET}"
fi

for role in "roles/owner" "roles/resourcemanager.folderAdmin" "roles/resourcemanager.projectCreator"; do
  gcloud resource-manager folders add-iam-policy-binding "$ARGOLIS_FOLDER_ID" \
    --member="user:${ARGOLIS_USER}" \
    --role="$role" \
    --condition=None \
    --quiet </dev/null >/dev/null
done
save_config

# Caller Quota / Seed Project (ensures user ADC X-Goog-User-Project succeeds during bootstrap)
EXISTING_CFG_QUOTA="$(gcloud config get-value billing/quota_project 2>/dev/null || true)"
USER_SLUG="$(echo "${ARGOLIS_DOMAIN%%.*}" | tr -cd 'a-z0-9-' | cut -c1-12)"
FALLBACK_QUOTA="isrg-seed-${USER_SLUG:-hipaa}"
DEFAULT_QUOTA_PROJ="${ARGOLIS_QUOTA_PROJECT:-${EXISTING_CFG_QUOTA:-$FALLBACK_QUOTA}}"

echo ""
info "Caller Quota Project: Human ADC credentials attach X-Goog-User-Project during project bootstrap."
prompt_val "Enter Caller Quota Project ID to create/reuse" "$DEFAULT_QUOTA_PROJ" ARGOLIS_QUOTA_PROJECT

if gcloud projects describe "$ARGOLIS_QUOTA_PROJECT" </dev/null >/dev/null 2>&1; then
  PROJ_STATE="$(gcloud projects describe "$ARGOLIS_QUOTA_PROJECT" --format="value(lifecycleState)" </dev/null 2>/dev/null || true)"
  if [[ "$PROJ_STATE" == "DELETE_REQUESTED" ]]; then
    warn "Quota project ${ARGOLIS_QUOTA_PROJECT} is pending deletion; restoring..."
    gcloud projects undelete "$ARGOLIS_QUOTA_PROJECT" </dev/null
  fi
  success "Quota project ${BOLD}${ARGOLIS_QUOTA_PROJECT}${RESET} already exists."
else
  info "Creating quota project ${BOLD}${ARGOLIS_QUOTA_PROJECT}${RESET} inside folders/${ARGOLIS_FOLDER_ID}..."
  gcloud projects create "$ARGOLIS_QUOTA_PROJECT" \
    --folder="$ARGOLIS_FOLDER_ID" \
    --name="Intuitive Terraform Seed" </dev/null
  success "Created quota project: ${BOLD}${ARGOLIS_QUOTA_PROJECT}${RESET}"
fi

BILLING_ENABLED="$(gcloud billing projects describe "$ARGOLIS_QUOTA_PROJECT" --format="value(billingEnabled)" </dev/null 2>/dev/null || true)"
if [[ "$BILLING_ENABLED" != "True" ]]; then
  info "Linking quota project ${ARGOLIS_QUOTA_PROJECT} to billing account ${ARGOLIS_BILLING_ACCOUNT}..."
  gcloud billing projects link "$ARGOLIS_QUOTA_PROJECT" --billing-account="$ARGOLIS_BILLING_ACCOUNT" </dev/null
fi

info "Enabling bootstrap control-plane APIs on ${ARGOLIS_QUOTA_PROJECT}..."
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  serviceusage.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  cloudbilling.googleapis.com \
  cloudkms.googleapis.com \
  storage.googleapis.com \
  logging.googleapis.com \
  --project="$ARGOLIS_QUOTA_PROJECT" </dev/null

gcloud config set project "$ARGOLIS_QUOTA_PROJECT" </dev/null >/dev/null
gcloud config set billing/quota_project "$ARGOLIS_QUOTA_PROJECT" </dev/null >/dev/null
gcloud auth application-default set-quota-project "$ARGOLIS_QUOTA_PROJECT" --quiet </dev/null >/dev/null
save_config
success "Configured ADC quota project: ${BOLD}${ARGOLIS_QUOTA_PROJECT}${RESET}"

echo ""
prompt_val "GCP Region for HIPAA Bucket, Cloud KMS & 6-Year Audit Vault" "${ARGOLIS_REGION:-us-central1}" ARGOLIS_REGION
prompt_val "Project ID prefix for the HIPAA Video PoC project" "${ARGOLIS_PROJECT_PREFIX:-isrg-hipaa-vid}" ARGOLIS_PROJECT_PREFIX
save_config

# ==============================================================================
# STEP 3/7: Render Sterilized Terraform Configuration (Idempotent via .template)
# ==============================================================================
banner "STEP 3/7: Rendering Terraform Variables from Sterilized Template"

sed \
  -e "s|__ARGOLIS_BILLING_ACCOUNT__|${ARGOLIS_BILLING_ACCOUNT}|g" \
  -e "s|__ARGOLIS_ORG_ID__|${ARGOLIS_ORG_ID}|g" \
  -e "s|__ARGOLIS_FOLDER_ID__|${ARGOLIS_FOLDER_ID}|g" \
  -e "s|__ARGOLIS_PROJECT_PREFIX__|${ARGOLIS_PROJECT_PREFIX}|g" \
  -e "s|__ARGOLIS_REGION__|${ARGOLIS_REGION}|g" \
  -e "s|__ARGOLIS_USER__|${ARGOLIS_USER}|g" \
  "$TFVARS_TEMPLATE" > "$TFVARS_FILE"

success "Rendered terraform/terraform.tfvars"
echo ""
echo -e "${BOLD}Configured HIPAA PoC Parameters:${RESET}"
echo -e "  • ${BOLD}Argolis Admin User:${RESET}      ${ARGOLIS_USER}"
echo -e "  • ${BOLD}Organization ID:${RESET}         ${ARGOLIS_ORG_ID}"
echo -e "  • ${BOLD}Billing Account ID:${RESET}      ${ARGOLIS_BILLING_ACCOUNT}"
echo -e "  • ${BOLD}Sandbox Parent Folder:${RESET}   folders/${ARGOLIS_FOLDER_ID} (${SANDBOX_FOLDER_NAME})"
echo -e "  • ${BOLD}Caller Quota Project:${RESET}    ${ARGOLIS_QUOTA_PROJECT}"
echo -e "  • ${BOLD}Deployment Region:${RESET}       ${ARGOLIS_REGION}"
echo -e "  • ${BOLD}PoC Project Prefix:${RESET}      ${ARGOLIS_PROJECT_PREFIX}-<random>"

# ==============================================================================
# STEP 4/7: Offline HIPAA Guardrail Unit Tests (terraform test)
# ==============================================================================
banner "STEP 4/7: Running Offline HIPAA Guardrail Unit Tests (terraform test)"

(
  cd "$TF_DIR"
  info "Initializing Terraform providers in ${TF_DIR}..."
  run_with_gpkg terraform init -upgrade -input=false >/dev/null
  info "Executing 'terraform test' (verifying UBLA, PAP, CMEK isolation, least-privilege IAM & 6-yr DATA_READ logs)..."
  terraform test
)
success "All offline HIPAA Terraform unit tests passed!"

# ==============================================================================
# STEP 5/7: Provisioning Argolis HIPAA Infrastructure (Plan & Apply)
# ==============================================================================
banner "STEP 5/7: Running 'terraform plan' & 'terraform apply'"

(
  cd "$TF_DIR"
  info "Generating Terraform execution plan..."
  terraform plan -out=tfplan

  if [[ "$AUTO_APPROVE" == "false" ]]; then
    echo ""
    read -r -p "Apply this Terraform plan to create/update the HIPAA PoC in Argolis now? [Y/n]: " DO_APPLY
    if [[ "$DO_APPLY" =~ ^[Nn]$ ]]; then
      warn "Skipped 'terraform apply'. Run './setup-argolis-sandbox.sh' anytime to resume."
      exit 0
    fi
  fi

  info "Applying Terraform plan (takes ~60-90s on first run to propagate APIs & KMS IAM)..."
  terraform apply "tfplan"
  rm -f tfplan
)
success "Argolis HIPAA V4 Signed URL + CMEK infrastructure provisioned!"

# ==============================================================================
# STEP 6/7: Automated 6-Stage End-to-End Live Verification
# ==============================================================================
banner "STEP 6/7: Running End-to-End HIPAA Signed URL + CMEK + Kill Switch Verification"

ensure_python_venv
"${VENV_DIR}/bin/python3" "${SCRIPT_DIR}/scripts/e2e_verify.py"

# ==============================================================================
# STEP 7/7: Sandbox Ready — Interactive Browser Demo & Share/Cleanup Commands
# ==============================================================================
DEPLOYED_PROJECT="$(terraform -chdir="$TF_DIR" output -raw project_id 2>/dev/null || echo '<project>')"
DEPLOYED_BUCKET="$(terraform -chdir="$TF_DIR" output -raw video_bucket_name 2>/dev/null || echo '<bucket>')"

echo ""
echo -e "${BOLD}${GREEN}================================================================================${RESET}"
echo -e "${BOLD}${GREEN}  ✅ SUCCESS: HIPAA V4 Signed URL + CMEK Sandbox Built & Verified End-to-End!${RESET}"
echo -e "${BOLD}${GREEN}================================================================================${RESET}"
echo -e "  • ${BOLD}Deployed Project:${RESET} ${DEPLOYED_PROJECT}"
echo -e "  • ${BOLD}Video Bucket:${RESET}     gs://${DEPLOYED_BUCKET}"
echo ""
echo -e "👉 ${BOLD}Useful Commands:${RESET}"
echo -e "   • Launch Browser Download UI : ${GREEN}./setup-argolis-sandbox.sh --portal${RESET}  ${DIM}(http://127.0.0.1:8080)${RESET}"
echo -e "   • Re-run E2E Test Suite      : ${GREEN}./setup-argolis-sandbox.sh --test-only${RESET}"
echo -e "   • Tear Down Cloud Resources  : ${GREEN}./setup-argolis-sandbox.sh --destroy${RESET}"
echo -e "   • Clean Local State to Share : ${GREEN}./setup-argolis-sandbox.sh --sterilize${RESET}"
echo ""

if [[ "$AUTO_APPROVE" == "false" ]]; then
  read -r -p "Would you like to launch the local Browser Download Portal (http://127.0.0.1:8080) now? [y/N]: " LAUNCH_PORTAL
  if [[ "$LAUNCH_PORTAL" =~ ^[Yy]$ ]]; then
    exec "${VENV_DIR}/bin/python3" "${SCRIPT_DIR}/scripts/portal_demo.py"
  fi
fi
