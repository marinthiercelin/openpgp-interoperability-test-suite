// Regular-expression-based filter for the results.

/* Courtesy of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions#escaping */
function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
}

const term = document.getElementById("search-input");
const note = document.getElementById("search-note");
const results = document.getElementById("search-results");

// Initialize on demand.
let initialized = false;
function initialize() {
    if (initialized) {
	return;
    }

    // Fix the current layout to prevent it from changing.

    // First, fix the width of the introduction.  This
    // takes care of the main column.
    const intro = document.getElementById("introduction");
    intro.style.width = `${intro.clientWidth}px`;

    // Second, fix the width of the navigation element.
    const nav = document.querySelector("nav");
    nav.style.width = `${nav.clientWidth}px`;

    initialized = true;
}

function search_on() {
    document.querySelectorAll(".hide-on-search")
        .forEach((e) => e.hidden = true);
    document.querySelectorAll(".show-on-search")
        .forEach((e) => e.hidden = false);
}

function search_off() {
    document.querySelectorAll(".hide-on-search, .test-result, .section-header")
        .forEach((e) => e.hidden = false);
    document.querySelectorAll(".show-on-search")
        .forEach((e) => e.hidden = true);
}

function filter_results() {
    initialize();

    if (term.value == "") {
        search_off();
        return;
    }

    let re;
    try {
        re = new RegExp(term.value, 'i');
        note.textContent = "";
    } catch (e) {
        const escaped = escapeRegExp(term.value);
        note.textContent =
            `Invalid regular expression, searching for "${escaped}" instead.`;
        re = new RegExp(escaped, 'i');
    }

    let current_section = null;
    let current_section_matched = false;
    while (results.firstChild) {
        results.removeChild(results.firstChild);
    }

    document.querySelectorAll(".test-result, .section-header").forEach((e) => {
        const test_title = e.querySelector("h3 a");
        if (test_title) {
            /* Found a test result.  */

            const description = e.querySelector(".description");
            const title = test_title.textContent;
            const matches = re.test(title) || re.test(description.innerHTML);
            e.hidden = ! matches;
            current_section_matched |= matches;

            if (matches) {
                const a = document.createElement("a");
                a.setAttribute("href", test_title.getAttribute("href"));
                a.textContent = title;
		const li = document.createElement("li");
		li.appendChild(a);
		results.appendChild(li);
	    }
	} else {
	    /* Found a new section header.  */

	    if (current_section) {
		current_section.hidden = ! current_section_matched;
	    }
	    current_section = e;
	    current_section_matched = false;
	}
    });
    if (current_section) {
	current_section.hidden = ! current_section_matched;
    }

    search_on();
}

term.addEventListener('input', filter_results);
term.addEventListener('search', filter_results);
term.focus();
