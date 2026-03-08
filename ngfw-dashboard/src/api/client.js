const BASE_URL = 'http://localhost:8000';

class ApiClient {
    async request(endpoint, options = {}) {
        const url = `${BASE_URL}${endpoint}`;
        const token = localStorage.getItem('auth_token');
        const headers = {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
            ...options.headers,
        };

        const config = {
            ...options,
            headers,
        };

        try {
            const response = await fetch(url, config);
            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.detail || `API error: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`API Request Failed: ${endpoint}`, error);
            // Provide better error messages for network failures
            if (error.message === 'Failed to fetch' || error.name === 'TypeError') {
                throw new Error('Unable to connect to server. Please ensure the backend server is running on http://localhost:8000');
            }
            // If error already has a message, use it; otherwise provide a generic one
            if (!error.message || error.message === 'Failed to fetch') {
                throw new Error('Network error: Could not reach the server. Please check your connection and ensure the backend is running.');
            }
            throw error;
        }
    }

    get(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'GET' });
    }

    post(endpoint, data, options = {}) {
        return this.request(endpoint, {
            ...options,
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    delete(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'DELETE' });
    }

    async upload(endpoint, file, options = {}) {
        const url = `${BASE_URL}${endpoint}`;
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(url, {
                ...options,
                method: 'POST',
                body: formData,
            });
            if (!response.ok) {
                throw new Error(`Upload failed: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`Upload Failed: ${endpoint}`, error);
            throw error;
        }
    }
}

export const apiClient = new ApiClient();
