# Use an official Python runtime as the base image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY ./app /app

# Install any needed packages specified in requirements.txt
RUN pip uninstall websocket websocket-client && pip install --trusted-host pypi.python.org -r requirements.txt

# Make port 80 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV NAME DataAccessManager

# Run app.py when the container launches
CMD ["python", "app.py"]
