// Метод 1: Add Parameter

// Код до рефакторингу
#include <iostream>
using namespace std;

class PaymentProcessor {
public:
    void ProcessPayment() {
        cout << "Processing payment..." << endl;
    }
};

int main() {
    PaymentProcessor processor;
    processor.ProcessPayment();
    return 0;
}

// Код після рефакторингу
#include <iostream>
using namespace std;

class PaymentProcessor {
public:
    void ProcessPayment(bool includeReceipt = false) {
        cout << "Processing payment..." << endl;
        if (includeReceipt) {
            cout << "Generating receipt for the payment..." << endl;
        }
    }
};

int main() {
    PaymentProcessor processor;
    processor.ProcessPayment();          
    processor.ProcessPayment(true);       
    return 0;
}

// Метод 2: Remove Parameter

// Код до рефакторингу
#include <iostream>
using namespace std;

class TemperatureLogger {
public:
    void LogTemperature(float value, string unit) {
        cout << "Temperature: " << value << " " << unit << endl;
    }
};

int main() {
    TemperatureLogger logger;
    logger.LogTemperature(36.5, "Celsius");
    return 0;
}

// Код після рефакторингу
#include <iostream>
using namespace std;

class TemperatureLogger {
public:
    void LogTemperature(float value) {
        cout << "Temperature: " << value << " Celsius" << endl;
    }
};

int main() {
    TemperatureLogger logger;
    logger.LogTemperature(36.5);
    return 0;
}

// Метод 3: Hide Delegate

// Код до рефакторингу
#include <iostream>
using namespace std;

class Printer {
public:
    void PrintDocument() {
        cout << "Document is being printed" << endl;
    }
};

class Office {
public:
    Printer printer;
};

int main() {
    Office office;
    office.printer.PrintDocument();
    return 0;
}

// Код після рефакторингу
#include <iostream>
using namespace std;

class Printer {
public:
    void PrintDocument() {
        cout << "Document is being printed" << endl;
    }
};

class Office {
private:
    Printer printer;

public:
    void StartPrinting() {
        printer.PrintDocument();
    }
};

int main() {
    Office office;
    office.StartPrinting(); 
    return 0;
}
