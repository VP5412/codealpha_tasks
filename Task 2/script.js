// Navigation State
let currentSlide = 0;
const slides = document.querySelectorAll('.slide');
const navDots = document.querySelectorAll('.nav-dot');
const btnPrev = document.getElementById('btn-prev');
const btnNext = document.getElementById('btn-next');
const slideIndicator = document.getElementById('current-slide-num');
const totalSlides = slides.length;

// Navigation Logic
function updateNavigation() {
    // Update slides
    slides.forEach((slide, index) => {
        if (index === currentSlide) {
            slide.classList.add('active');
        } else {
            slide.classList.remove('active');
        }
    });

    // Update dots
    navDots.forEach((dot, index) => {
        if (index === currentSlide) {
            dot.classList.add('active');
        } else {
            dot.classList.remove('active');
        }
    });

    // Update controls
    btnPrev.disabled = currentSlide === 0;
    btnNext.disabled = currentSlide === totalSlides - 1;
    slideIndicator.textContent = currentSlide + 1;
}

function nextSlide() {
    if (currentSlide < totalSlides - 1) {
        currentSlide++;
        updateNavigation();
    }
}

function prevSlide() {
    if (currentSlide > 0) {
        currentSlide--;
        updateNavigation();
    }
}

function goToSlide(index) {
    if (index >= 0 && index < totalSlides) {
        currentSlide = index;
        updateNavigation();
    }
}

// Add event listeners to dots
navDots.forEach(dot => {
    dot.addEventListener('click', () => {
        goToSlide(parseInt(dot.dataset.index));
    });
});

// Interactive Anatomy Slide Logic
const hoverables = document.querySelectorAll('.hoverable');
const infoCard = document.getElementById('anatomy-info');

hoverables.forEach(item => {
    item.addEventListener('mouseenter', (e) => {
        const info = e.target.getAttribute('data-info');
        infoCard.innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="color:var(--primary-red)"></i><p>${info}</p>`;
        infoCard.style.borderColor = 'var(--primary-red)';
    });

    item.addEventListener('mouseleave', () => {
        infoCard.innerHTML = `<i class="fa-solid fa-circle-info"></i><p>Interact with the email on the right to learn more.</p>`;
        infoCard.style.borderColor = 'var(--glass-border)';
    });
});


// Quiz Logic
const quizData = [
    {
        question: "Which of the following is a common sign of a phishing email?",
        options: [
            "It addresses you by your full name.",
            "It creates a sense of extreme urgency.",
            "It comes from someone you know (and you were expecting it).",
            "It contains no links or attachments."
        ],
        correct: 1,
        explanation: "Phishers use urgency to make you panic and click links or share info without thinking critically."
    },
    {
        question: "You receive an email from 'IT Dept' asking you to verify your password immediately. What should you do?",
        options: [
            "Click the link and enter your password quickly.",
            "Forward the email to your friends to warn them.",
            "Contact IT directly using verified contact info, not the email links.",
            "Reply to the email asking if it's real."
        ],
        correct: 2,
        explanation: "Never trust contact info or links provided in a suspicious email. Always verify through a trusted secondary channel."
    },
    {
        question: "What is 'Spear Phishing'?",
        options: [
            "A generic blast of emails to millions of people.",
            "A physical attack on a server room.",
            "A highly targeted phishing attack crafted for a specific individual.",
            "A tool used to scan for malware."
        ],
        correct: 2,
        explanation: "Spear phishing uses personal info gathered about you (e.g., from LinkedIn) to make the fake email seem highly customized and legitimate."
    }
];

let currentQuestion = 0;
let score = 0;
let quizCompleted = false;

// DOM Elements
const quizIntro = document.getElementById('quiz-intro');
const quizQuestion = document.getElementById('quiz-question');
const quizResults = document.getElementById('quiz-results');

const questionText = document.getElementById('question-text');
const optionsContainer = document.getElementById('options-container');
const progressFill = document.getElementById('quiz-progress');
const feedbackMessage = document.getElementById('feedback-message');

function startQuiz() {
    quizIntro.classList.add('hidden');
    quizQuestion.classList.remove('hidden');
    currentQuestion = 0;
    score = 0;
    quizCompleted = false;
    loadQuestion();
}

function loadQuestion() {
    const q = quizData[currentQuestion];
    questionText.textContent = `${currentQuestion + 1}. ${q.question}`;
    
    // Update progress
    const progress = ((currentQuestion) / quizData.length) * 100;
    progressFill.style.width = `${progress}%`;

    // Clear previous options and feedback
    optionsContainer.innerHTML = '';
    feedbackMessage.className = 'hidden';
    feedbackMessage.innerHTML = '';

    q.options.forEach((opt, index) => {
        const btn = document.createElement('button');
        btn.className = 'option-btn';
        btn.textContent = opt;
        btn.onclick = () => selectOption(index, btn);
        optionsContainer.appendChild(btn);
    });
}

function selectOption(index, btnElement) {
    // Disable all options
    const allOptions = optionsContainer.querySelectorAll('.option-btn');
    allOptions.forEach(btn => btn.onclick = null);

    const q = quizData[currentQuestion];
    const isCorrect = index === q.correct;

    if (isCorrect) {
        score++;
        btnElement.classList.add('correct');
        feedbackMessage.innerHTML = `<i class="fa-solid fa-circle-check"></i> Correct! ${q.explanation}`;
        feedbackMessage.className = 'feedback-success';
    } else {
        btnElement.classList.add('wrong');
        // Highlight correct option
        allOptions[q.correct].classList.add('correct');
        feedbackMessage.innerHTML = `<i class="fa-solid fa-circle-xmark"></i> Incorrect. ${q.explanation}`;
        feedbackMessage.className = 'feedback-error';
    }

    // Add Next Button
    const nextBtn = document.createElement('button');
    nextBtn.className = 'btn-primary';
    nextBtn.style.marginTop = '20px';
    nextBtn.innerHTML = currentQuestion === quizData.length - 1 ? 'See Results' : 'Next Question <i class="fa-solid fa-arrow-right"></i>';
    nextBtn.onclick = () => {
        currentQuestion++;
        if (currentQuestion < quizData.length) {
            loadQuestion();
        } else {
            showResults();
        }
    };
    
    feedbackMessage.appendChild(document.createElement('br'));
    feedbackMessage.appendChild(nextBtn);
}

function showResults() {
    quizQuestion.classList.add('hidden');
    quizResults.classList.remove('hidden');
    
    document.getElementById('score-text').textContent = score;
    document.getElementById('total-text').textContent = quizData.length;
    
    const resultMsg = document.getElementById('result-message');
    if (score === quizData.length) {
        resultMsg.textContent = "Perfect! You have a sharp eye for phishing attacks.";
    } else if (score > 0) {
        resultMsg.textContent = "Good job! Review the best practices to stay even safer.";
    } else {
        resultMsg.textContent = "You might want to review the previous slides to stay safe out there.";
    }
}

function resetQuiz() {
    quizResults.classList.add('hidden');
    quizIntro.classList.remove('hidden');
}

// Keyboard navigation
document.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight') {
        nextSlide();
    } else if (e.key === 'ArrowLeft') {
        prevSlide();
    }
});

// Initialize
updateNavigation();
