/**
 * FraudLens Centralized API Configuration and Authentication Client.
 *
 * Configures the base URL for the FastAPI backend gateway.
 * Defaults to http://127.0.0.1:8000 with optional override via VITE_API_URL.
 */

export const API_BASE_URL: string =
  (import.meta.env.VITE_API_URL as string) || 'http://127.0.0.1:8000';

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  created_at: string;
}

export interface AuthResponseData {
  user: AuthUser;
  token: string;
  token_type: string;
}

const TOKEN_KEY = 'fraudlens_auth_token';
const USER_KEY = 'fraudlens_auth_user';

export const getStoredToken = (): string | null => {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
};

export const getStoredUser = (): AuthUser | null => {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
};

export const setStoredAuth = (user: AuthUser, token: string): void => {
  try {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } catch {
    // LocalStorage fallback
  }
};

export const clearStoredAuth = (): void => {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  } catch {
    // LocalStorage fallback
  }
};

/**
 * Safely extracts a user-readable error message from FastAPI error responses.
 * Handles:
 * - Simple string detail (e.g. "Invalid credentials")
 * - Pydantic validation error lists: [{ loc: [...], msg: "Value error, Unsupported URL scheme...", type: "..." }]
 * - Removes internal prefixes like "Value error, " for cleaner UI presentation
 * - Objects with a message or msg property
 * - Fallbacks if parsing fails or error is unknown
 */
export const extractApiErrorMessage = (
  errorData: unknown,
  fallbackMessage: string = 'An unexpected error occurred'
): string => {
  if (!errorData) return fallbackMessage;

  // Case 1: errorData is a string
  if (typeof errorData === 'string') {
    return errorData.replace(/^Value error,\s*/i, '').trim();
  }

  // Case 2: errorData is an object with detail property
  if (typeof errorData === 'object' && errorData !== null) {
    const data = errorData as Record<string, unknown>;

    if (typeof data.detail === 'string') {
      return data.detail.replace(/^Value error,\s*/i, '').trim();
    }

    // Detail is an array of Pydantic validation errors
    if (Array.isArray(data.detail) && data.detail.length > 0) {
      const messages = data.detail
        .map((err) => {
          if (typeof err === 'string') return err.replace(/^Value error,\s*/i, '').trim();
          if (typeof err === 'object' && err !== null) {
            const item = err as Record<string, unknown>;
            if (typeof item.msg === 'string') {
              return item.msg.replace(/^Value error,\s*/i, '').trim();
            }
            if (typeof item.message === 'string') {
              return item.message.replace(/^Value error,\s*/i, '').trim();
            }
          }
          return '';
        })
        .filter(Boolean);

      if (messages.length > 0) {
        return messages.join('. ');
      }
    }

    if (typeof data.message === 'string') {
      return data.message.replace(/^Value error,\s*/i, '').trim();
    }
  }

  return fallbackMessage;
};

export const loginUser = async (email: string, password: string): Promise<AuthResponseData> => {
  const res = await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(extractApiErrorMessage(errorData, `Login failed with status ${res.status}`));
  }

  const data: AuthResponseData = await res.json();
  setStoredAuth(data.user, data.token);
  return data;
};

export const signupUser = async (name: string, email: string, password: string): Promise<AuthResponseData> => {
  const res = await fetch(`${API_BASE_URL}/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(extractApiErrorMessage(errorData, `Signup failed with status ${res.status}`));
  }

  const data: AuthResponseData = await res.json();
  setStoredAuth(data.user, data.token);
  return data;
};

export const fetchCurrentUser = async (token: string): Promise<AuthUser | null> => {
  try {
    const res = await fetch(`${API_BASE_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.ok) {
      const user: AuthUser = await res.json();
      localStorage.setItem(USER_KEY, JSON.stringify(user));
      return user;
    } else {
      clearStoredAuth();
      return null;
    }
  } catch {
    return null;
  }
};

export const logoutUser = async (): Promise<void> => {
  const token = getStoredToken();
  if (token) {
    try {
      await fetch(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch {
      // Ignore network errors on logout
    }
  }
  clearStoredAuth();
};
