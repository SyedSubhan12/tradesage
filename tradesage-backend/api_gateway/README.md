# API Gateway Overview

The API Gateway serves as the central entry point for all client requests to the Tradesage backend services. It handles routing, authentication, rate limiting, and load balancing, ensuring secure and efficient communication between clients and microservices.

## Features

- **Routing**: Directs incoming requests to the appropriate microservice based on URL paths.
- **Authentication**: Validates JWT tokens and manages session security before forwarding requests.
- **Rate Limiting**: Prevents abuse by limiting the number of requests a client can make within a specific timeframe.
- **Load Balancing**: Distributes incoming traffic across multiple instances of services to ensure scalability and reliability.
- **Logging and Monitoring**: Tracks requests and responses for debugging and performance analysis.
- **Security**: Implements CORS policies and other security headers to protect against common vulnerabilities.

## Working Flow

1. **Request Reception**: The API Gateway receives HTTP requests from clients.
2. **Authentication Check**: Validates the JWT token and session. If invalid, returns a 401 Unauthorized response.
3. **Rate Limiting**: Checks if the client has exceeded request limits. If exceeded, returns a 429 Too Many Requests response.
4. **Routing**: Matches the request path to the configured service endpoints and forwards the request to the appropriate microservice.
5. **Response Handling**: Receives the response from the microservice and forwards it back to the client, adding any necessary headers or modifications.

## Architecture

The API Gateway is built using FastAPI, leveraging its asynchronous capabilities for high performance. It integrates with Redis for rate limiting and session management, and it communicates with other microservices like Auth and Session services for token validation.

- **Core Components**:
  - `main.py`: Entry point for the FastAPI app, setting up middleware, routes, and service discovery. It includes authentication middleware, CORS setup, and Prometheus metrics for monitoring.
  - `config.py`: Stores configuration settings for service endpoints and environment variables.
  - Middleware for authentication, logging, CORS, and rate limiting.

- **Dependencies**:
  - **FastAPI**: For building the gateway application.
  - **Redis**: For rate limiting and caching (though not directly visible in `main.py`, it's implied through session management).
  - **HTTPX**: For making asynchronous HTTP requests to downstream services.
  - **Structlog**: For structured logging of requests and errors.
  - **Starlette**: For middleware and response handling.
  - **Prometheus**: For metrics and monitoring via the `/metrics` endpoint.

- **Middleware**:
  - **CORS Middleware**: Configured to allow specific origins, credentials, and all methods/headers for cross-origin requests.
  - **Authentication Middleware**: Validates JWT tokens for non-public API paths, allowing OPTIONS requests and public paths to bypass authentication.
  - **Prometheus Middleware**: Tracks performance metrics, accessible via the `/metrics` endpoint.

## Load Balancing in `main.py`

Contrary to a round-robin strategy, the current implementation in `main.py` does not explicitly implement load balancing with multiple service instances:

- **Static Routing**: The gateway routes requests to predefined service URLs (e.g., `AUTH_SERVICE_URL`, `SESSION_SERVICE_URL`) without dynamic instance selection or health checks for multiple instances.
- **Direct Proxying**: Requests are proxied to a single downstream URL per service type using `httpx.AsyncClient` for asynchronous communication.

This indicates that load balancing, if any, must be handled externally (e.g., via DNS or a separate load balancer) or is a planned feature not yet implemented in the code.

## Additional Features in `main.py`

- **Health Check Endpoint**: A `/health` endpoint checks the gateway's status and the health of downstream services like Auth and Session. It returns a detailed status report, marking the gateway as unhealthy (503) if any dependency fails.
- **Public Path Handling**: Certain API paths can be configured as public (exact matches or prefixes) to bypass authentication, useful for login or registration endpoints.
- **OAuth Proxy**: Special handling for `/oauth/` paths to forward requests without the `/api` prefix, facilitating external authentication callbacks.
- **SPA Static File Serving**: The gateway attempts to serve a Single Page Application (SPA) from a frontend build directory (e.g., `frontend/dist`), mounting it at the root path with HTML support for client-side routing.

## Flaws and Limitations

- **Single Point of Failure**: As the central entry point, if the API Gateway fails, the entire system becomes inaccessible. High availability setups (e.g., multiple gateway instances behind a load balancer) are recommended.
- **No Dynamic Load Balancing**: The current code does not implement internal load balancing or service discovery for multiple instances of a microservice, potentially leading to bottlenecks if a single service instance is overwhelmed.
- **Latency Overhead**: Additional latency is introduced due to the extra hop through the gateway and the authentication/rate-limiting checks.
- **Configuration Complexity**: Managing service endpoints statically in configuration can become cumbersome as the number of microservices grows.
- **Rate Limiting Bottleneck**: Heavy reliance on Redis for rate limiting (if implemented in middleware) can create bottlenecks if Redis performance degrades under high load.
- **Static SPA Path Dependency**: The code for serving static SPA files relies on hardcoded paths, which may not be portable across environments or setups.

## Potential Improvements

- Implement dynamic service discovery and load balancing algorithms (e.g., round-robin, least connections) within the gateway to handle multiple service instances.
- Deploy multiple gateway instances with a higher-level load balancer for redundancy.
- Enhance caching strategies to reduce load on downstream services.
- Use service discovery tools like Consul or Eureka for dynamic endpoint management.
- Add configurable paths for SPA static file serving to improve deployment flexibility.
- Incorporate more robust error handling and fallback mechanisms for downstream service failures.

For setup and deployment instructions, refer to the main project documentation.