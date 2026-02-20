/**
 * Standard API response shape for all endpoints.
 * Ensures consistent structure across the microservice.
 */
export interface ApiResponse<T = unknown> {
  /** Whether the request succeeded. */
  success: boolean;
  /** Human-readable message. */
  message: string;
  /** Payload or null when no data. */
  data: T | null;
  /** ISO 8601 timestamp. */
  timestamp: string;
}
