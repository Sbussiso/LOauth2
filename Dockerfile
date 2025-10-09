# Use official uv image
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Sync dependencies using uv
RUN uv sync --frozen

# Expose port
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the application with uv
CMD ["uv", "run", "gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "server:app"]
