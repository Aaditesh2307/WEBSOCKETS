#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#include <iostream>
#include <string>
#include <functional>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <thread>

// Define WebSocket++ Client Type for secure WebSocket (wss://)
typedef websocketpp::client<websocketpp::config::asio_tls_client> client;

class WebSocketClient
{
public:
    WebSocketClient()
    {
        // Initialize WebSocket++ client (with TLS)
        m_client.init_asio();

        // Bind event handlers
        m_client.set_open_handler(std::bind(&WebSocketClient::on_open, this, std::placeholders::_1));
        m_client.set_message_handler(std::bind(&WebSocketClient::on_message, this, std::placeholders::_1, std::placeholders::_2));
        m_client.set_close_handler(std::bind(&WebSocketClient::on_close, this, std::placeholders::_1));
        m_client.set_fail_handler(std::bind(&WebSocketClient::on_fail, this, std::placeholders::_1));

        // Set the TLS initialization handler
        m_client.set_tls_init_handler(std::bind(&WebSocketClient::on_tls_init, this, std::placeholders::_1));
    }

    // Connect to the WebSocket server (with TLS)
    void connect(const std::string &uri)
    {
        websocketpp::lib::error_code ec;
        client::connection_ptr con = m_client.get_connection(uri, ec);

        if (ec)
        {
            std::cerr << "Connection error: " << ec.message() << std::endl;
            return;
        }

        m_handle = con->get_handle();
        m_client.connect(con);

        m_client.run();
    }

    // Send a message to the WebSocket server
    void send(const std::string &message)
    {
        websocketpp::lib::error_code ec;
        m_client.send(m_handle, message, websocketpp::frame::opcode::text, ec);

        if (ec)
        {
            std::cerr << "Send error: " << ec.message() << std::endl;
        }
    }

private:
    client m_client;                      // WebSocket++ client instance
    websocketpp::connection_hdl m_handle; // Connection handle

    // Event Handlers
    void on_open(websocketpp::connection_hdl hdl)
    {
        std::cout << "Connected to server." << std::endl;
    }

    void on_message(websocketpp::connection_hdl hdl, client::message_ptr msg)
    {
        std::cout << "Received message: " << msg->get_payload() << std::endl;
    }

    void on_close(websocketpp::connection_hdl hdl)
    {
        std::cout << "Connection closed." << std::endl;
    }

    void on_fail(websocketpp::connection_hdl hdl)
    {
        std::cerr << "Connection failed." << std::endl;
    }

    // TLS initialization handler (corrected signature)
    std::shared_ptr<boost::asio::ssl::context> on_tls_init(websocketpp::connection_hdl)
    {
        auto ctx = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv12);
        ctx->set_verify_mode(boost::asio::ssl::context::verify_none); // Disable certificate verification
        return ctx;
    }
};

// Command-Line Interface for Interaction
int main()
{
    WebSocketClient ws_client;

    const std::string uri = "wss://echo.websocket.org"; // Use secure WebSocket (wss://)

    // Start the WebSocket client in a separate thread to avoid blocking
    std::cout << "Connecting to WebSocket server at: " << uri << std::endl;
    std::thread client_thread([&]()
                              { ws_client.connect(uri); });

    // Handle user input for sending messages
    std::string message;
    while (true)
    {
        std::cout << "Enter a message to send (type 'exit' to quit): ";
        std::getline(std::cin, message);

        if (message == "exit")
        {
            break;
        }

        ws_client.send(message);
    }

    // Wait for the client thread to finish
    client_thread.join();
    return 0;
}
