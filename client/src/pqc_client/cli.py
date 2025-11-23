import click
import grpc
import logging

# Import local and generated modules
from . import channel
from .generated import health_pb2
from .generated import health_pb2_grpc
from .generated import pqc_pb2
from .generated import pqc_pb2_grpc

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.group()
def main():
    """PQC Client - A command-line interface for the PQC server."""
    pass


@main.command()
@click.option('--server', default='localhost:50051', help='Server address (host:port)')
@click.option('--ca-cert', default='/app/certs/ca.crt', help='Path to CA certificate')
@click.option('--client-cert', default='/app/certs/client.crt', help='Path to client certificate')
@click.option('--client-key', default='/app/certs/client.key', help='Path to client private key')
def health(server, ca_cert, client_cert, client_key):
    """Check the health status of the PQC server."""
    click.echo(f"Checking health of server at {server}...")

    try:
        # Create secure channel
        secure_channel = channel.create_secure_channel(
            server, ca_cert, client_cert, client_key
        )

        # Create health check stub
        stub = health_pb2_grpc.HealthStub(secure_channel)

        # Send health check request
        request = health_pb2.HealthCheckRequest(service="")
        response = stub.Check(request)

        # Display result
        status_name = health_pb2.HealthCheckResponse.ServingStatus.Name(response.status)
        click.echo(f"Server status: {status_name}")

        if response.status == health_pb2.HealthCheckResponse.SERVING:
            click.echo("✓ Server is healthy and ready to accept requests")
        else:
            click.echo("✗ Server is not serving")

    except grpc.RpcError as e:
        click.echo(f"Error: {e.code()} - {e.details()}", err=True)
    except Exception as e:
        click.echo(f"Unexpected error: {str(e)}", err=True)


@main.command()
@click.argument('message')
@click.option('--server', default='localhost:50051', help='Server address (host:port)')
@click.option('--ca-cert', default='/app/certs/ca.crt', help='Path to CA certificate')
@click.option('--client-cert', default='/app/certs/client.crt', help='Path to client certificate')
@click.option('--client-key', default='/app/certs/client.key', help='Path to client private key')
def store(message, server, ca_cert, client_cert, client_key):
    """Store a message on the PQC server."""
    click.echo(f"Storing message on server at {server}...")

    try:
        # Create secure channel
        secure_channel = channel.create_secure_channel(
            server, ca_cert, client_cert, client_key
        )

        # Create PQC service stub - FIXED: Use correct stub name
        stub = pqc_pb2_grpc.PQCStringStoreStub(secure_channel)

        # Send store request
        request = pqc_pb2.StoreRequest(message=message)
        response = stub.Store(request)

        click.echo(f"✓ Message stored successfully. ID: {response.id}")

    except grpc.RpcError as e:
        click.echo(f"Error: {e.code()} - {e.details()}", err=True)
    except Exception as e:
        click.echo(f"Unexpected error: {str(e)}", err=True)


@main.command()
@click.argument('message_id', type=int)
@click.option('--server', default='localhost:50051', help='Server address (host:port)')
@click.option('--ca-cert', default='/app/certs/ca.crt', help='Path to CA certificate')
@click.option('--client-cert', default='/app/certs/client.crt', help='Path to client certificate')
@click.option('--client-key', default='/app/certs/client.key', help='Path to client private key')
def retrieve(message_id, server, ca_cert, client_cert, client_key):
    """Retrieve a message from the PQC server by ID."""
    click.echo(f"Retrieving message ID {message_id} from server at {server}...")

    try:
        # Create secure channel
        secure_channel = channel.create_secure_channel(
            server, ca_cert, client_cert, client_key
        )

        # Create PQC service stub - FIXED: Use correct stub name
        stub = pqc_pb2_grpc.PQCStringStoreStub(secure_channel)

        # Send retrieve request
        request = pqc_pb2.RetrieveRequest(id=message_id)
        response = stub.Retrieve(request)

        click.echo(f"✓ Message retrieved: {response.message}")

    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.NOT_FOUND:
            click.echo(f"✗ Message with ID {message_id} not found", err=True)
        else:
            click.echo(f"Error: {e.code()} - {e.details()}", err=True)
    except Exception as e:
        click.echo(f"Unexpected error: {str(e)}", err=True)


@main.command(name='upload-file')
@click.argument('filepath')
@click.option('--server', default='localhost:50051', help='Server address (host:port)')
@click.option('--ca-cert', default='/app/certs/ca.crt', help='Path to CA certificate')
@click.option('--client-cert', default='/app/certs/client.crt', help='Path to client certificate')
@click.option('--client-key', default='/app/certs/client.key', help='Path to client private key')
def upload(filepath, server, ca_cert, client_cert, client_key):
    """Upload a file to the server."""
    import os

    if not os.path.exists(filepath):
        click.echo(f"Error: File {filepath} not found.", err=True)
        return

    filename = os.path.basename(filepath)
    click.echo(f"Uploading {filename} to server at {server}...")

    try:
        secure_channel = channel.create_secure_channel(server, ca_cert, client_cert, client_key)
        stub = pqc_pb2_grpc.PQCStringStoreStub(secure_channel)

        def request_generator():
            # Send metadata first
            metadata = pqc_pb2.FileMetadata(filename=filename)
            yield pqc_pb2.UploadFileRequest(metadata=metadata)

            # Send chunks
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(64 * 1024) # 64KB chunks
                    if not chunk:
                        break
                    yield pqc_pb2.UploadFileRequest(chunk=chunk)

        response = stub.UploadFile(request_generator())
        click.echo(f"✓ File uploaded successfully. ID: {response.id}, Size: {response.size} bytes")

    except grpc.RpcError as e:
        click.echo(f"Error: {e.code()} - {e.details()}", err=True)
    except Exception as e:
        click.echo(f"Unexpected error: {str(e)}", err=True)


@main.command(name='download-file')
@click.argument('file_id')
@click.argument('output_path')
@click.option('--server', default='localhost:50051', help='Server address (host:port)')
@click.option('--ca-cert', default='/app/certs/ca.crt', help='Path to CA certificate')
@click.option('--client-cert', default='/app/certs/client.crt', help='Path to client certificate')
@click.option('--client-key', default='/app/certs/client.key', help='Path to client private key')
def download(file_id, output_path, server, ca_cert, client_cert, client_key):
    """Download a file from the server."""
    click.echo(f"Downloading {file_id} from server at {server}...")

    try:
        secure_channel = channel.create_secure_channel(server, ca_cert, client_cert, client_key)
        stub = pqc_pb2_grpc.PQCStringStoreStub(secure_channel)

        request = pqc_pb2.DownloadFileRequest(id=file_id)
        response_iterator = stub.DownloadFile(request)

        with open(output_path, 'wb') as f:
            for response in response_iterator:
                f.write(response.chunk)

        click.echo(f"✓ File downloaded successfully to {output_path}")

    except grpc.RpcError as e:
        click.echo(f"Error: {e.code()} - {e.details()}", err=True)
    except Exception as e:
        click.echo(f"Unexpected error: {str(e)}", err=True)


if __name__ == '__main__':
    main()
