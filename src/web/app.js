function toggleDescription(userId) {
    const description = document.getElementById(`${userId}Description`);
    const toggle = document.getElementById(`${userId}Toggle`);
    description.classList.toggle('hidden');
    toggle.querySelector('svg').classList.toggle('flipped-icon');
}

function formatAIResponse(markdown) {
    markdown = markdown.replace(/^(#{1,6})\s*(.+)$/gm, (match, hashes, content) => {
        const level = hashes.length;
        return `<h${level}>${content}</h${level}>`;
    });

    markdown = markdown.replace(/\*\*(.*?)\*\*|\_\_(.*?)\_\_/g, '<strong>$1$2</strong>');

    markdown = markdown.replace(/\*(.*?)\*|\_(.*?)\_/g, '<em>$1$2</em>');

    markdown = markdown.replace(/^([*+-])\s+(.*)$/gm, '<ul><li>$2</li></ul>');

    markdown = markdown.replace(/^(\d+)\.\s+(.*)$/gm, '<ol><li>$2</li></ol>');

    markdown = markdown.replace(/\[([^\]]+)\]\((.*?)\)/g, '<a href="$2">$1</a>');

    markdown = markdown.replace(/\n/g, '<br>');

    markdown = markdown.replace(/^([^\n]+)$/gm, '<p>$1</p>');

    return markdown;
}


function fetchAISolution(cveId, buttonElement) {
    const parentCell = buttonElement.closest('td');

    const existingResponse = parentCell.querySelector('.ai-response');
    if (existingResponse) {
        existingResponse.remove();
        return;
    }

    buttonElement.disabled = true;
    const originalContent = buttonElement.innerHTML;
    buttonElement.innerHTML = `
        <span class="relative px-3 py-1.5 transition-all ease-in duration-75 bg-white dark:bg-gray-900 rounded-md group-hover:bg-opacity-0 flex justify-center items-center gap-1">
            Loading...
        </span>
    `;

    fetch(`/api/ai?cve_id=${cveId}`)
        .then(response => response.json())
        .then(data => {
            const responseDiv = document.createElement('div');
            responseDiv.className = 'ai-response mt-5 p-4 bg-gray-50 rounded-lg';
            responseDiv.innerHTML = `
                <h4 class="font-medium text-base mb-2">AI Analysis</h4>
                <div class="text-sm text-gray-600">
                    ${data ?  formatAIResponse(data) : 'No AI solution available'}
                </div>
            `;

            buttonElement.after(responseDiv);
        })
        .catch(error => {
            console.log(error)
            const errorDiv = document.createElement('div');
            errorDiv.className = 'ai-response mt-5 p-4 bg-red-50 text-red-600 rounded-lg';
            errorDiv.textContent = 'Failed to fetch AI analysis. Please try again.';
            buttonElement.after(errorDiv);
        })
        .finally(() => {
            buttonElement.disabled = false;
            buttonElement.innerHTML = originalContent;
        });
}

let tableState = {
    originalData: [],
    filteredData: [],
    currentSearchTerm: '',
    filters: {
        severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
    },
    sort: {
        column: null,
        direction: 'asc'
    }
};

function renderTable() {
    const tbody = document.querySelector('tbody');
    if (!tbody) return;

    tbody.innerHTML = tableState.filteredData.map((item, index) => {
        let severityColor = 'bg-gray-500';
        if (item.vulnerability.severity.level === 'CRITICAL') {
            severityColor = 'bg-red-500';
        } else if (item.vulnerability.severity.level === 'HIGH') {
            severityColor = 'bg-orange-500';
        } else if (item.vulnerability.severity.level === 'MEDIUM') {
            severityColor = 'bg-yellow-500'
        } else if (item.vulnerability.severity.level === 'LOW') {
            severityColor = 'bg-blue-500'
        }

        return `
            <tr class="py-10 cursor-pointer border-b border-gray-200 hover:bg-gray-100" 
                onclick="toggleDescription('cve${index}')">
                <td class="px-4 py-4">
                    <div class="flex-1 pl-1">
                        <div class="font-medium dark:text-white">${item.metadata.id}</div>
                    </div>
                </td>
                <td class="px-4 py-4">${item.affected.product}</td>
                <td>
                    <div class="flex items-center pl-1">
                        <div class="w-2 h-2 ${severityColor} rounded-full mr-2"></div>
                        ${item.vulnerability.severity.level ? item.vulnerability.severity.level : 'UNKNOWN'}
                    </div>
                </td>
                <td class="px-4">${item.metadata.state}</td>
                <td class="p-4">
                    <div id="cve${index}Toggle" class="text-white bg-gray-100 border rounded-lg px-4 py-4 text-center inline-flex items-center">
                        <svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                            <path d="M11.9997 13.1714L16.9495 8.22168L18.3637 9.63589L11.9997 15.9999L5.63574 9.63589L7.04996 8.22168L11.9997 13.1714Z"></path>
                        </svg>
                    </div>
                </td>
            </tr>
            <tr id="cve${index}Description" class="hidden py-4 px-4 border-t border-gray-200">
                <td colspan="4" class="p-8">
                    <h4 class="font-medium text-base mb-2">Vulnerability Description</h4>
                    <p class="text-sm text-gray-600">${item.vulnerability.description}</p>
                    <div class="relative overflow-x-auto mt-5">
                        <table class="w-full text-sm text-left rtl:text-right text-gray-500 dark:text-gray-400">
                            <thead class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-700 dark:text-gray-400">
                                <tr>
                                    <th scope="col" class="py-3">
                                        Severity Level
                                    </th>
                                    <th scope="col" class="py-3">
                                        Base Score
                                    </th>
                                    <th scope="col" class="py-3">
                                        Vector
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr class="bg-white border-b dark:bg-gray-800 dark:border-gray-700">
                                    <th scope="row" class=" py-4 font-medium text-gray-900 whitespace-nowrap dark:text-white">
                                        ${item.vulnerability.severity.level ? item.vulnerability.severity.level : 'UNKNOWN'}
                                    </th>
                                    <td class="py-4">
                                        ${item.vulnerability.severity.baseScore ? item.vulnerability.severity.baseScore : 'N/A'}
                                    </td>
                                    <td class="py-4">
                                        ${item.vulnerability.severity.vector ? item.vulnerability.severity.vector : 'N/A'}
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="mt-5">
                        <h4 class="font-medium text-base mb-2">Common Weakness Enumeration</h4>
                        ${item.problemTypes.reference ? 
                            `<a href="${item.problemTypes.reference}" class="text-sm text-blue-600 hover:underline" target="_blank" rel="noopener noreferrer">${item.problemTypes.description}</a>` :
                            `<p class="text-sm text-gray-600">${item.problemTypes.description}</p>`
                        }
                    </div>                 
                    <div class="mt-5"> 
                        <h4 class="font-medium text-base mb-2">National Institute of Standards and Technology</h4> 
                        <a target="_blank" rel="noopener noreferrer"  class="text-sm text-blue-600 dark:text-blue-500 hover:underline" href="https://nvd.nist.gov/vuln/detail/${item.cve_id}">https://nvd.nist.gov/vuln/detail/${item.cve_id}</a>
                    </div>
                    <div class="mt-5">
                        <h4 class="font-medium text-base mb-2">References</h4>
                        <div class="mt-2">
                            ${Array.isArray(item.references)
            ? item.references.map(ref => `
                                <div>
                                    <a target="_blank" rel="noopener noreferrer" class="text-sm text-blue-600 dark:text-blue-500 hover:underline" href=${typeof ref === 'string' ? ref : ref.url || JSON.stringify(ref)}>${typeof ref === 'string' ? ref : ref.url || JSON.stringify(ref)}</a>
                                </div>
                                `).join('')
            : 'No references available'
        }
                        </div>
                    </div>
                    <div class="mt-5">
                        <h4 class="font-medium text-base mb-2">Potential Solution</h4>
                        <p class="text-sm text-gray-600">${item.vulnerability.solution ? item.vulnerability.solution : "Not Specified"}</p>
                    </div>
                    <button onclick="event.stopPropagation(); fetchAISolution('${item.metadata.id}', this)" 
                            class="mt-8 relative inline-flex items-center justify-center p-0.5 mb-2 me-2 overflow-hidden text-xs font-medium text-gray-900 rounded-lg group bg-gradient-to-br from-cyan-500 to-blue-500 group-hover:from-cyan-500 group-hover:to-blue-500 hover:text-white dark:text-white focus:ring-4 focus:outline-none focus:ring-cyan-200 dark:focus:ring-cyan-800">
                        <span class="relative px-3 py-1.5 transition-all ease-in duration-75 bg-white dark:bg-gray-900 rounded-md group-hover:bg-opacity-0 flex justify-center items-center gap-1">
                            AI Solution
                            <svg class="w-4 h-4" viewBox="0 0 512 416" xmlns="http://www.w3.org/2000/svg" fill-rule="evenodd" clip-rule="evenodd" stroke-linejoin="round" stroke-miterlimit="2"><path d="M181.33 266.143c0-11.497 9.32-20.818 20.818-20.818 11.498 0 20.819 9.321 20.819 20.818v38.373c0 11.497-9.321 20.818-20.819 20.818-11.497 0-20.818-9.32-20.818-20.818v-38.373zM308.807 245.325c-11.477 0-20.798 9.321-20.798 20.818v38.373c0 11.497 9.32 20.818 20.798 20.818 11.497 0 20.818-9.32 20.818-20.818v-38.373c0-11.497-9.32-20.818-20.818-20.818z" fill-rule="nonzero"/><path d="M512.002 246.393v57.384c-.02 7.411-3.696 14.638-9.67 19.011C431.767 374.444 344.695 416 256 416c-98.138 0-196.379-56.542-246.33-93.21-5.975-4.374-9.65-11.6-9.671-19.012v-57.384a35.347 35.347 0 016.857-20.922l15.583-21.085c8.336-11.312 20.757-14.31 33.98-14.31 4.988-56.953 16.794-97.604 45.024-127.354C155.194 5.77 226.56 0 256 0c29.441 0 100.807 5.77 154.557 62.722 28.19 29.75 40.036 70.401 45.025 127.354 13.263 0 25.602 2.936 33.958 14.31l15.583 21.127c4.476 6.077 6.878 13.345 6.878 20.88zm-97.666-26.075c-.677-13.058-11.292-18.19-22.338-21.824-11.64 7.309-25.848 10.183-39.46 10.183-14.454 0-41.432-3.47-63.872-25.869-5.667-5.625-9.527-14.454-12.155-24.247a212.902 212.902 0 00-20.469-1.088c-6.098 0-13.099.349-20.551 1.088-2.628 9.793-6.509 18.622-12.155 24.247-22.4 22.4-49.418 25.87-63.872 25.87-13.612 0-27.86-2.855-39.501-10.184-11.005 3.613-21.558 8.828-22.277 21.824-1.17 24.555-1.272 49.11-1.375 73.645-.041 12.318-.082 24.658-.288 36.976.062 7.166 4.374 13.818 10.882 16.774 52.97 24.124 103.045 36.278 149.137 36.278 46.01 0 96.085-12.154 149.014-36.278 6.508-2.956 10.84-9.608 10.881-16.774.637-36.832.124-73.809-1.642-110.62h.041zM107.521 168.97c8.643 8.623 24.966 14.392 42.56 14.392 13.448 0 39.03-2.874 60.156-24.329 9.28-8.951 15.05-31.35 14.413-54.079-.657-18.231-5.769-33.28-13.448-39.665-8.315-7.371-27.203-10.574-48.33-8.644-22.399 2.238-41.267 9.588-50.875 19.833-20.798 22.728-16.323 80.317-4.476 92.492zm130.556-56.008c.637 3.51.965 7.35 1.273 11.517 0 2.875 0 5.77-.308 8.952 6.406-.636 11.847-.636 16.959-.636s10.553 0 16.959.636c-.329-3.182-.329-6.077-.329-8.952.329-4.167.657-8.007 1.294-11.517-6.735-.637-12.812-.965-17.924-.965s-11.21.328-17.924.965zm49.275-8.008c-.637 22.728 5.133 45.128 14.413 54.08 21.105 21.454 46.708 24.328 60.155 24.328 17.596 0 33.918-5.769 42.561-14.392 11.847-12.175 16.322-69.764-4.476-92.492-9.608-10.245-28.476-17.595-50.875-19.833-21.127-1.93-40.015 1.273-48.33 8.644-7.679 6.385-12.791 21.434-13.448 39.665z"/></svg>
                        </span>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function applySearchAndFilters(searchTerm = '') {
    tableState.currentSearchTerm = searchTerm.toLowerCase().trim();

    tableState.filteredData = tableState.originalData.filter(item => {
        const cveId = item?.metadata?.id?.toLowerCase() || '';
        const matchesSearch = !tableState.currentSearchTerm ||
            cveId === tableState.currentSearchTerm ||
            cveId.startsWith(tableState.currentSearchTerm) ||
            cveId.includes(tableState.currentSearchTerm);

        const severity = item.vulnerability.severity.level || 'UNKNOWN';
        const matchesFilter = tableState.filters.severity.includes(severity);

        return matchesSearch && matchesFilter;
    });

    renderTable();
}

function createTableRow() {
    fetch('/api/cve')
        .then(response => response.json())
        .then(data => {
            tableState.originalData = data;
            tableState.filteredData = data;
            renderTable();
        });
}

function filter() {
    const dropdownMenu = document.getElementById('dropdownDefaultCheckbox');
    const checkboxes = dropdownMenu?.querySelectorAll('input[type="checkbox"]');

    checkboxes?.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const value = this.value;
            const isChecked = this.checked;

            if (isChecked) {
                if (!tableState.filters.severity.includes(value)) {
                    tableState.filters.severity.push(value);
                }
            } else {
                tableState.filters.severity = tableState.filters.severity.filter(v => v !== value);
            }
            applySearchAndFilters(tableState.currentSearchTerm);
        });
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('default-search');
    if (!searchInput) {
        console.error('Search input not found');
        return;
    }

    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value;
        applySearchAndFilters(searchTerm);
    });
});

window.onload = () => {
    createTableRow();
    filter();
};