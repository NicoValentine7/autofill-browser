export const WORKER_BASE_URL = "https://autofill-browser-log-worker.y-elucidator.workers.dev"
export const PRODUCT_OPERATION_LOG_WORKER_BASE_URL = "https://product-operation-logs.y-elucidator.workers.dev"

export const buildCloudWorkerUrl = (pathname: "/me" | "/me/settings" | "/me/events" | "/me/rules") => `${WORKER_BASE_URL}${pathname}`

export const buildProductOperationLogWorkerUrl = (pathname: "/events") => {
  const baseUrl = PRODUCT_OPERATION_LOG_WORKER_BASE_URL.trim()
  return baseUrl ? `${baseUrl}${pathname}` : ""
}

export const CLOUD_LOG_INCLUDE_FIELD_VALUES = false
