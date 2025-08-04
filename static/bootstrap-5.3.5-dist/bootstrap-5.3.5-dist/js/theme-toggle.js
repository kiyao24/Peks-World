document.addEventListener('DOMContentLoaded', () => {
    const html = document.documentElement;
    const storedTheme = localStorage.getItem('theme');
    if (storedTheme) {
        html.setAttribute('data-theme', storedTheme);
    }

    const toggleBtn = document.getElementById('toggle-theme');
    toggleBtn.addEventListener('click', () => {
        const current = html.getAttribute('data-theme');
        const newTheme = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    });
});
