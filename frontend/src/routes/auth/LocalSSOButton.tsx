import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { router } from "@/app/router";

// Dev/test OIDC login served by the backend (see backend/api/localsso).
const CONFIG_ENDPOINT = "/api/local-sso/config";
const LOGIN_ENDPOINT = "/api/local-sso/login";

type LocalSSOConfig = { enabled: boolean; title: string };

const ERROR_CODES = [
  "denied",
  "failed",
  "not_registered",
  "state",
  "unverified",
] as const;
type ErrorCode = (typeof ERROR_CODES)[number];

export const parseErrorCode = (value: unknown): ErrorCode | undefined =>
  ERROR_CODES.find((code) => code === value);

export function LocalSSOButton() {
  const { t } = useTranslation();
  const [config, setConfig] = useState<LocalSSOConfig>();
  const errorCode = parseErrorCode(router.currentRoute.value.query.sso_error);

  useEffect(() => {
    let cancelled = false;
    fetch(CONFIG_ENDPOINT, { credentials: "same-origin" })
      .then((res) => (res.ok ? res.json() : undefined))
      .then((data: LocalSSOConfig | undefined) => {
        if (!cancelled && data?.enabled) setConfig(data);
      })
      .catch(() => {
        // The login page works without it.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!config) return null;
  const title = config.title || "SSO";
  return (
    <div className="mb-4 flex flex-col gap-y-2">
      {errorCode && (
        <Alert
          variant="warning"
          title={t("local-sso.failed", { title })}
          description={t(`local-sso.error.${errorCode}`)}
        />
      )}
      <Button
        appearance="outline"
        size="lg"
        className="w-full"
        onClick={() => {
          window.location.href = LOGIN_ENDPOINT;
        }}
      >
        {t("local-sso.continue", { title })}
      </Button>
    </div>
  );
}
