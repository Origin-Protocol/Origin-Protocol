interface ImportMetaEnv {
  readonly DEV?: boolean;
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_ABIGAIL_BASE_URL?: string;
  readonly VITE_ABIGAIL_API_KEY?: string;
  readonly VITE_ABIGAIL_TENANT_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}