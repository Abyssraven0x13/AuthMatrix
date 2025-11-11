# AuthMatrix (Community-Maintained Version)



---

### ⚠️ **Notice: This is a Community-Maintained Fork**

This is an actively maintained fork of the original **AuthMatrix** project by **SecurityInnovation** ([github.com/SecurityInnovation/AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)).

The original project appears to be unmaintained (last commit in [Year of last commit, e.g., 2018]). This fork was created to continue its development, fix outstanding bugs, incorporate modern Burp Suite APIs, and add new features for the community.

All credit for the original concept and foundational code goes to SecurityInnovation.

---

## What is AuthMatrix?

AuthMatrix is a Burp Suite extension designed to help security testers identify authorization vulnerabilities. It provides a simple and intuitive way to test complex, matrix-based access control models in web applications and web services.

This extension allows testers to define a set of users, roles, and "chains" (requests) to verify that an application's authentication and authorization controls are working as intended.

## New Features in This Fork

This version includes all the original functionality of AuthMatrix, plus the following enhancements:

* ✅ **[Your Feature 1]**: (e.g., Added support for JSON Web Tokens (JWT) in headers)
* ✅ **[Your Feature 2]**: (e.g., Integrated with Burp's new Logger component)
* 🐛 **[Your Bug Fix 1]**: (e.g., Fixed a critical bug where session handling would fail on new Java versions)
* 🔧 **[Your Update 1]**: (e.g., Updated all libraries to be compatible with the latest Burp Suite Java version)
* *...[List your other changes here]...*

## Installation

### 1. BApp Store (Recommended)

This extension is available in the Burp Suite **BApp Store**. This is the easiest way to install and stay updated.

1.  Go to the **Extender** tab in Burp Suite.
2.  Click the **BApp Store** sub-tab.
3.  Search for "AuthMatrix".
4.  Click **Install**.

*(Note: If you are submitting this to the BApp store for the first time, replace the text above with "Coming soon to the BApp Store!")*

### 2. Manual Installation (Build from Source)

If you prefer to build it yourself:

1.  Clone this repository:
    ```bash
    git clone [https://github.com/](https://github.com/)[YOUR_USERNAME]/[YOUR_REPOSITORY_NAME].git
    ```
2.  Build the project using [Your build method, e.g., Gradle or Maven]:
    ```bash
    ./gradlew fatJar
    ```
3.  Go to the **Extender** tab in Burp Suite.
4.  Click **Add** and select the "Java" extension type.
5.  Load the generated `AuthMatrix-all.jar` file from the `/build/libs/` directory.

## Usage

For detailed usage instructions, please refer to the **original project's Wiki**. The core concepts remain the same.

* **[Original Wiki Link](https://github.com/SecurityInnovation/AuthMatrix/wiki)**

*(Note: The original Wiki may not reflect the new features added in this fork. We are working on updating the documentation.)*

## Contributing

Contributions are very welcome! If you find a bug, have a feature request, or want to improve the code, please:

1.  Fork this repository (the new one, not the original).
2.  Create a new branch for your feature or bugfix.
3.  Submit a Pull Request with a clear description of your changes.

## License

This project is licensed under the **Apache License 2.0**, in accordance with the original project.

This is a derivative work of the original AuthMatrix. The original `LICENSE` file and notices from the SecurityInnovation repository are preserved in this project as required.
