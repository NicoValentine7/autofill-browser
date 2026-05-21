export const WORKER_BASE_URL = "https://autofill-browser-log-worker.y-elucidator.workers.dev"

export const buildCloudWorkerUrl = (pathname: "/me" | "/me/settings" | "/me/events") => `${WORKER_BASE_URL}${pathname}`

export const CLOUD_LOG_INCLUDE_FIELD_VALUES = true
