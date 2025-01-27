# Cybersecurity Analysis Project

## Overview
This project provides a simple Node.js web application designed to simulate a small-scale task management system. The application has intentional issues to serve as a learning platform for analyzing security vulnerabilities and application stability.

Your task is to examine the provided code, identify vulnerabilities, and propose improvements to enhance security and reliability.

## Application Features
- **User Registration and Login**: Users can register with a username and password, and log in to access protected features.
- **Task Management**: Authenticated users can add, view, and delete tasks.
- **Session Management**: The application uses session middleware to manage user sessions.
- **Static File Serving**: 
  - Unprotected files (`login.html`, `register.html`) are served from the `public` folder.
  - Protected files (`index.html`, `dashboard.html`) are served from the `private/protected` folder and require authentication.

## Structure
- **Public Routes**:
  - `POST /register`: Register a new user.
  - `POST /login`: Authenticate an existing user.
  - `GET /public/login.html`: Serve the login page.
  - `GET /public/register.html`: Serve the registration page.
- **Protected Routes**:
  - `GET /`: Redirect to the dashboard or login based on session status.
  - `GET /dashboard`: Serve the dashboard page for authenticated users.
  - `POST /add`: Add a task for the logged-in user.
  - `GET /tasks`: Retrieve tasks for the logged-in user.
  - `DELETE /tasks/:id`: Delete a task by ID.
  - `GET /logout`: Log out the current user.

## Your Task
1. **Analyze the Code**:
   - Review the codebase provided in the repository.
   - Identify all security vulnerabilities and areas where errors are not handled properly.

2. **Develop Static Files**:
   - Create the necessary HTML files for the `public` and `private/protected` folders:
     - `login.html`: A user-friendly login page.
     - `register.html`: A registration page with a form.
     - `index.html`: The main dashboard page for logged-in users.
     - `dashboard.html`: A page for managing tasks.
   - The dashboard should include two sections:
     - **Add Task Section**: A form to add new tasks.
     - **Task Display Section**: A table that lists all tasks retrieved from the server.
   - Use modern CSS to create a visually appealing layout and user experience.
   - Implement functionality using only vanilla JavaScript, the Fetch API, and DOM manipulation.

3. **Document Vulnerabilities and Errors**:
   - For each issue, explain the potential impact and suggest a solution to mitigate the problem.

4. **Submit a Report**:
   - Your report should include:
     - A list of identified vulnerabilities.
     - A list of unhandled error scenarios.
     - Proposed solutions for each issue.

## Installation and Setup

### Prerequisites
- Node.js (v14 or higher)
- npm (Node Package Manager)

### Installation Steps
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd task-manager
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

### Running the Application
1. Start the server:
   ```bash
   npm start
   ```

2. Access the application:
   - Open your browser and navigate to:
     - Login: http://localhost:3000/public/login.html
     - Register: http://localhost:3000/public/register.html

### Usage Guide

1. **Registration**:
   - Navigate to http://localhost:3000/public/register.html
   - Fill in username and password
   - Click "Register"

2. **Login**:
   - Navigate to http://localhost:3000/public/login.html
   - Enter credentials
   - Click "Login"

3. **Task Management**:
   - Add Task:
     - Fill in task title and description
     - Click "Add Task"
   - View Tasks:
     - All tasks are displayed in the task list
   - Delete Task:
     - Click the delete button next to any task

4. **Logout**:
   - Click "Logout" to end your session

## Troubleshooting

### Common Issues
1. **Port Already in Use**: Change the port in `.env` file
2. **Database Issues**: Check file permissions for database.json
3. **Session Errors**: Clear browser cookies

### Security Notes
- Change default credentials in production
- Use HTTPS in production environment
- Set secure session cookies in production
- Regularly update dependencies

## Deliverables
- The final project, including all developed files and the implemented functionalities.
- A detailed report of vulnerabilities and error scenarios.
- Developed static files (html and js) with well-designed layouts and CSS.
- A functional dashboard with task addition and display sections implemented using vanilla JavaScript.

## Notes
- This project is intentionally insecure. Do not deploy it in a production environment.
- Focus on analysis and understanding rather than implementing fixes immediately.

Good luck!
