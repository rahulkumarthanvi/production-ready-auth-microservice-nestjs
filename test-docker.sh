#!/bin/bash

# Docker Testing Script for Auth Microservice

echo "🐳 Docker Testing Guide"
echo "========================"
echo ""

# Check Docker
echo "1. Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi
echo "✅ Docker is installed: $(docker --version)"

if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not available."
    exit 1
fi
echo "✅ Docker Compose is available: $(docker compose version)"
echo ""

# Check .env file
echo "2. Checking environment configuration..."
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "✅ Created .env file. Please edit it and set JWT secrets!"
    else
        echo "❌ .env.example not found!"
        exit 1
    fi
else
    echo "✅ .env file exists"
fi
echo ""

# Check if containers are running
echo "3. Checking running containers..."
if docker compose ps | grep -q "Up"; then
    echo "⚠️  Containers are already running!"
    echo "   Use 'docker compose down' to stop them first"
    read -p "   Do you want to stop and restart? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker compose down
    else
        echo "   Keeping existing containers running"
        exit 0
    fi
fi
echo ""

# Build and start
echo "4. Building and starting containers..."
echo "   This may take a few minutes on first run..."
docker compose up --build -d

# Wait for services to be healthy
echo ""
echo "5. Waiting for services to be ready..."
sleep 5

# Check health
echo ""
echo "6. Testing API health endpoint..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -s http://localhost:3000/api/v1/health > /dev/null 2>&1; then
        echo "✅ API is healthy!"
        curl -s http://localhost:3000/api/v1/health | jq '.' 2>/dev/null || curl -s http://localhost:3000/api/v1/health
        break
    else
        attempt=$((attempt + 1))
        echo "   Attempt $attempt/$max_attempts - Waiting for API..."
        sleep 2
    fi
done

if [ $attempt -eq $max_attempts ]; then
    echo "❌ API did not become healthy. Check logs: docker compose logs app"
    exit 1
fi

echo ""
echo "7. Container Status:"
docker compose ps

echo ""
echo "✅ Docker setup is complete!"
echo ""
echo "📋 Useful Commands:"
echo "   View logs:        docker compose logs -f app"
echo "   Stop containers:  docker compose stop"
echo "   Remove all:       docker compose down -v"
echo "   API URL:          http://localhost:3000/api/v1"
echo "   Swagger Docs:     http://localhost:3000/api/docs"
echo ""
