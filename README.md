# Chirpy

Chirpy is a simple social media application where users can post short messages called "chirps". This project demonstrates a basic web application built with Go, PostgreSQL, and various other technologies.

## Features

- User authentication and authorization
- Create, read, update, and delete chirps
- Fetch chirps by user ID
- Sort chirps in ascending or descending order
- Webhooks for handling external events

## Why Chirpy?

Chirpy is a great starting point for anyone looking to learn how to build a web application with Go and PostgreSQL. It covers essential features like user authentication, CRUD operations, and handling webhooks, making it a valuable resource for both beginners and experienced developers.

## Installation

### Prerequisites

- Go 1.16 or later
- PostgreSQL 12 or later
- `goose` for database migrations
- `sqlc` for generating type-safe Go code from SQL queries

### Clone the Repository

```sh
git clone git@github.com:andersonfpcorrea/Chirpy.git
cd chirpy
```

### Set Up Environment Variables

Create a .env file in the root directory of the project and add the following environment variables:

```sh
DB_URL=postgres://username:password@localhost:5432/chirpy
PLATFORM=your_platform
JWT_SECRET=your_jwt_secret
POLKA_KEY=your_polka_key
```

### Install Dependencies

```sh
go mod tidy
```

### Run Database Migrations

```sh
goose -dir ./migrations postgres "postgres://username:password@localhost:5432/chirpy" up
```

### Generate Go Code from SQL Queries

```sh
sqlc generate
```

## Running the Project

### Start the server

```sh
go run .
```

The server will start on http://localhost:8080.

## API Endpoints

### User Endpoints

- POST /api/users: Create a new user
- PUT /api/users: Update user email and password
- POST /api/refresh: Refresh JWT token
- POST /api/revoke: Revoke refresh token

### Chirp Endpoints

- POST /api/chirps: Create a new chirp
- GET /api/chirps: Get all chirps (with optional sorting and filtering by user ID)
- GET /api/chirps/{id}: Get a specific chirp by ID
- DELETE /api/chirps/{id}: Delete a chirp by ID

### Webhook Endpoints

- POST /api/polka/webhooks: Handle external events from Polka (fake company)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

MIT
