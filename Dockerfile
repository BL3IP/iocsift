FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# Run as a non-root user
RUN useradd --create-home sift
USER sift

ENTRYPOINT ["iocsift"]
CMD ["--help"]
