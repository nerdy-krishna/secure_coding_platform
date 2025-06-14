---
sidebar_position: 2
title: LLM Configuration
---

# LLM Configuration API

These endpoints are used to manage the LLM provider configurations for the platform.

**Base URL:** `/api/v1/admin/llm-configs`

:::danger Permissions
All endpoints in this section require **Superuser** authentication.
:::

## Create LLM Configuration

Creates a new LLM provider configuration. The provided API key will be encrypted at rest.

-   **Endpoint:** `POST /`
-   **Permissions:** Superuser
-   **Request Body:**

    ```json
    {
      "name": "OpenAI GPT-4o",
      "provider": "openai",
      "model_name": "gpt-4o",
      "api_key": "sk-..."
    }
    ```

-   **Response (`201 Created`):**

    ```json
    {
      "name": "OpenAI GPT-4o",
      "provider": "openai",
      "model_name": "gpt-4o",
      "id": "e4a2c9c0-a1b2-c3d4-e5f6-1234567890ab"
    }
    ```

## List LLM Configurations

Retrieves a list of all available LLM configurations. API keys are not included in the response.

-   **Endpoint:** `GET /`
-   **Permissions:** Any Authenticated User
-   **Response (`200 OK`):**

    ```json
    [
      {
        "name": "OpenAI GPT-4o",
        "provider": "openai",
        "model_name": "gpt-4o",
        "id": "e4a2c9c0-a1b2-c3d4-e5f6-1234567890ab"
      },
      {
        "name": "Google Gemini 1.5",
        "provider": "google",
        "model_name": "gemini-1.5-pro-latest",
        "id": "f8b7e6d5-c4b3-a2a1-b0c9-0987654321fe"
      }
    ]
    ```

## Delete LLM Configuration

Deletes an LLM configuration by its unique ID.

-   **Endpoint:** `DELETE /{config_id}`
-   **Permissions:** Superuser
-   **URL Parameters:**
    -   `config_id` (string, UUID): The ID of the configuration to delete.
-   **Response:**
    -   `204 No Content`: If the deletion was successful.
    -   `404 Not Found`: If no configuration with the given ID exists.