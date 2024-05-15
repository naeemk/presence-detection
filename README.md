# Program Setup Guide

This guide will walk you through setting up and running the `main.py` program. The program utilizes various modules and libraries, so proper setup is essential for smooth execution.

## Prerequisites

Ensure you have the following installed:

- Python (version 3.6 or higher)
- `pip` package manager
- `scapy`, `tkinter`, and other required libraries (install via pip)

## Installation Steps

1. **Clone the Repository**: Clone the repository containing the `main.py` file onto your local machine.

   ```bash
   git clone <repository_url>
   ```

2. **Navigate to the Directory**: Enter the directory where `main.py` is located.

   ```bash
   cd <repository_directory>
   ```

3. **Install Dependencies**: Install the required Python packages using `pip`.

   ```bash
   pip install scapy tkinter matplotlib
   ```

4. **Additional Setup**: Depending on your operating system and network configuration, you might need to configure additional settings like network interfaces or permissions. Refer to the documentation of the libraries used in the program for detailed instructions.

## Running the Program

Once you've completed the setup steps, you can run the program by executing the `main.py` file.

```bash
python main.py
```

Follow any on-screen instructions or prompts provided by the program. Depending on its functionality, it might require specific permissions or access to certain resources on your system.

## Program Overview

- **`main.py`**: This is the main script of the program.
- **Modules and Functions**: The program utilizes various modules and functions stored in the `functions` directory. These modules handle tasks such as packet sniffing, data processing, and UI setup.
- **Objects**: The program uses objects such as `ProbeRequest` and `Device` stored in the `objects` directory to represent network entities.
- **GUI Component**: The program includes a GUI component built using the `tkinter` library for user interaction and visualization.
- **Data Visualization**: Data visualization is achieved using `matplotlib` for plotting graphs and charts.

## Additional Notes

- **Customization**: You can customize the program by modifying parameters, adding new functionalities, or extending existing modules.
- **Troubleshooting**: If you encounter any issues during setup or execution, refer to the documentation of the libraries used or seek assistance from online communities and forums.
- **Security Considerations**: Depending on the nature of your network operations, ensure that the program's activities comply with security policies and regulations.

## Support and Feedback

For any questions, feedback, or support regarding the program, feel free to reach out to the program's maintainers or community forums associated with the libraries used.

---

By following these steps, you should be able to successfully set up and run the `main.py` program on your system. If you encounter any difficulties or have further questions, don't hesitate to ask for assistance!
