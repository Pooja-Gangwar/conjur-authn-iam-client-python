# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the required Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire current directory into the container
COPY . .

# Run the unittest command when the container starts
# CMD ["python3.9", "-m", "unittest", "discover"]
CMD ["python3.9", "-m", "unittest"]

