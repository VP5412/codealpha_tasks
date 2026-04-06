# Task 2 — Phishing Awareness Training Module

An interactive, browser-based cybersecurity training module that teaches users how to recognize and defend against phishing attacks. Built as a pure front-end single-page application — no server or installation required.

---

## Features

- **5-slide interactive presentation** covering the full phishing threat landscape
- **Anatomy of a Fake Email** — hover over highlighted elements in a simulated phishing email to reveal hidden red flags
- **Social Engineering Tactics** — visual cards explaining common manipulation techniques
- **Best Practices Guide** — actionable security tips for everyday users
- **Interactive Quiz** — 3-question knowledge check with instant feedback and explanations
- **Keyboard navigation** — use the `←` / `→` arrow keys to move between slides
- **Dot navigation bar** — jump directly to any slide via the side nav
- Responsive, modern dark UI with glassmorphism styling and smooth transitions

---

## Project Structure

```
Task 2/
├── index.html    # Main HTML file — all slides, quiz, and layout
├── script.js     # Slide navigation logic, quiz engine, hover interactions
├── styles.css    # Full styling: dark theme, glassmorphism, animations
└── assets/
    └── hero.png  # Hero illustration for the introduction slide
```

### Key Components

| File | Role |
|---|---|
| `index.html` | Defines the 5 slide sections, the floating nav dots, bottom Previous/Next controls, and the fake email interactive element |
| `script.js` | Manages slide state, drives the quiz lifecycle (`startQuiz` → `loadQuestion` → `selectOption` → `showResults`), and wires hover events for the anatomy slide |
| `styles.css` | Dark glassmorphism theme, slide transitions, quiz option states (correct/wrong highlight), and responsive layout |

---

## Slide Overview

| Slide | Title | Content |
|---|---|---|
| 1 | Introduction | Welcome screen with "Don't Get Hooked" hero section |
| 2 | Anatomy of a Fake Email | Interactive simulated phishing email with hoverable red-flag tooltips |
| 3 | Social Engineering Tactics | Four glass cards: False Urgency, Authority Spoofing, Baiting, Spear Phishing |
| 4 | How to Stay Secure | Checklist: Verify Source, Hover Before Click, Enable MFA, Use a Password Manager |
| 5 | Interactive Quiz | 3 multiple-choice questions with per-answer feedback and a final score |

---

## Requirements

- Any modern web browser (Chrome, Firefox, Edge, Safari)
- An internet connection to load Google Fonts and Font Awesome icons (CDN-linked)
- No server, build tools, or installation needed

---

## Usage

1. Open `index.html` directly in your browser (double-click the file, or drag it into a browser window).
2. Click **Start Training** on the introduction slide to begin.
3. Navigate between slides using:
   - The **Next** / **Previous** buttons at the bottom
   - The **dot navigation** on the right side
   - The **← / →** keyboard arrow keys
4. On Slide 2, hover over the highlighted words in the fake email to reveal red-flag explanations.
5. On Slide 5, click **Begin Quiz**, answer each question, and review feedback after each answer.
6. After completing the quiz, your score is displayed with a personalized result message. Click **Try Again** to restart the quiz.

---

## Quiz Details

The quiz contains 3 questions covering:

1. Recognizing common signs of a phishing email (e.g., false urgency)
2. Correct response when receiving a suspicious IT request
3. Definition and characteristics of Spear Phishing

Each question provides:
- Immediate correct/incorrect visual feedback on the selected option
- The correct answer highlighted if the user was wrong
- A short explanation paragraph to reinforce learning
- A "Next Question" / "See Results" button to progress

---

## Technologies Used

| Technology | Purpose |
|---|---|
| HTML5 | Page structure and slide content |
| CSS3 | Glassmorphism styling, animations, responsive layout |
| Vanilla JavaScript | Navigation state, quiz logic, interactive hover effects |
| Google Fonts | Inter and Outfit typefaces |
| Font Awesome 6 | Icons throughout the UI |
