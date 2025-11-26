// IoT Door Lock Logic for ESP32
// SSID: JL-Sol
// Password: mjl_062822
// IP: 192.168.1.3
// LED Red: D12 (Door Locked)
// LED Green: D14 (Door Unlocked, also T4 for capacitive touch)
// Push Button: D25
// Capacitive Touch: D14 (T4)

#include <WiFi.h>

#define LED_RED 12
#define LED_GREEN 14
#define BUTTON_PIN 25
#define TOUCH_PIN T4

const char* ssid = "JL-Sol";
const char* password = "mjl_062822";

WiFiServer server(80);
bool doorLocked = true;

void setup() {
  Serial.begin(115200);
  pinMode(LED_RED, OUTPUT);
  pinMode(LED_GREEN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
  Serial.println(WiFi.localIP());
  server.begin();
  updateLeds();
}

void updateLeds() {
  digitalWrite(LED_RED, doorLocked ? HIGH : LOW);
  digitalWrite(LED_GREEN, doorLocked ? LOW : HIGH);
}

void toggleDoor() {
  doorLocked = !doorLocked;
  updateLeds();
  Serial.println(doorLocked ? "Door Locked" : "Door Unlocked");
}

void loop() {
  // Button
  if (digitalRead(BUTTON_PIN) == LOW) {
    delay(50);
    if (digitalRead(BUTTON_PIN) == LOW) {
      toggleDoor();
      while (digitalRead(BUTTON_PIN) == LOW) delay(10);
    }
  }
  // Capacitive Touch
  if (touchRead(TOUCH_PIN) < 30) {
    toggleDoor();
    delay(500);
  }
  // Handle web requests
  WiFiClient client = server.available();
  if (client) {
    String req = "";
    unsigned long timeout = millis() + 1000;
    while (client.connected() && millis() < timeout) {
      if (client.available()) {
        char c = client.read();
        req += c;
        if (req.endsWith("\r\n\r\n")) break;
      }
    }
    // Parse HTTP method and path
    bool isGet = req.startsWith("GET /status");
    bool isPost = req.startsWith("POST /lock");
    if (isGet) {
      // Respond with JSON status
      String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
      resp += "{\"locked\":";
      resp += (doorLocked ? "true" : "false");
      resp += ",\"source\":\"esp32\"}";
      client.print(resp);
    } else if (isPost) {
      // Read body (very basic, expects {"locked":true/false})
      String body = "";
      while (client.available()) body += (char)client.read();
      int idx = body.indexOf("locked");
      if (idx != -1) {
        int valIdx = body.indexOf(":", idx);
        if (valIdx != -1) {
          String val = body.substring(valIdx+1);
          val.trim();
          if (val.startsWith("true")) doorLocked = true;
          else if (val.startsWith("false")) doorLocked = false;
          updateLeds();
        }
      }
      String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
      resp += "{\"locked\":";
      resp += (doorLocked ? "true" : "false");
      resp += ",\"source\":\"esp32\"}";
      client.print(resp);
    } else {
      // Not found
      client.print("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\n\r\nNot found");
    }
    delay(1);
    client.stop();
  }
}
