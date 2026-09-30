import { createSignal, onMount } from 'https://esm.sh/solid-js@1.8.22';
import { createStore } from 'https://esm.sh/solid-js@1.8.22/store';
import { render } from 'https://esm.sh/solid-js@1.8.22/web';
import { VAEFuzzOptimizer } from './ml.js';

function App() {
    const [state, setState] = createStore({ status: 'Running', results: [], generated: [] });
    const [searchFuzz, setSearchFuzz] = createSignal('');
    const [searchGen, setSearchGen] = createSignal('');
    const optimizer = new VAEFuzzOptimizer();

    onMount(() => {
        const evtSource = new EventSource('/api/stream');
        evtSource.onmessage = (e) => {
            const data = JSON.parse(e.data);
            if (data.type === 'progress') {
                const item = data.item;
                const metrics = optimizer.ingestPair(item.target, item.status, item.duration_us || 0);
                
                const enrichedItem = { 
                    ...item, 
                    pairLoss: metrics.pairLoss, 
                    latentZ: metrics.latentZ, 
                    gradNorm: metrics.gradNorm 
                };
                setState('results', r => [enrichedItem, ...r]);
                setState('generated', optimizer.getGenerated().slice().reverse());
            } else if (data.type === 'complete') {
                setState('status', 'Complete');
                evtSource.close();
            }
        };
    });

    return (() => {
        const container = document.createElement('div');
        container.className = "min-h-screen bg-slate-50 text-slate-800 p-6 font-mono text-xs";
        container.innerHTML = `
            <style>
                .no-scrollbar::-webkit-scrollbar { display: none; }
                .no-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
            </style>
            <div class="max-w-6xl mx-auto space-y-6">
                <header class="flex justify-between items-center border-b border-slate-200 pb-4">
                    <div>
                        <h1 class="text-sm font-bold tracking-tight text-slate-900">Alpine Fuzzing & Diffusion VAE</h1>
                        <p class="text-[11px] text-slate-500">Batch Size 1 • Diffusion Denoising • Backprop Loss & Latent Z-State Tracking</p>
                    </div>
                    <div class="px-3 py-1 rounded bg-white border border-slate-200 shadow-sm">
                        Status: <span id="status-badge" class="text-amber-600 font-semibold">Running</span>
                    </div>
                </header>

                <!-- Concurrent Fuzzing Stream Section -->
                <section class="space-y-2">
                    <div class="flex justify-between items-center">
                        <h2 class="text-xs font-bold text-slate-700 uppercase tracking-wider">Exhaustive Concurrent Fuzzing Stream</h2>
                        <input id="search-fuzz-input" type="text" placeholder="Fuzzy search binaries..." class="px-2.5 py-1 w-64 bg-white border border-slate-200 rounded text-xs focus:outline-none focus:border-slate-400" />
                    </div>
                    <div class="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden">
                        <div class="max-h-80 overflow-y-auto no-scrollbar">
                            <table class="w-full text-left border-collapse">
                                <thead class="sticky top-0 bg-slate-50 border-b border-slate-200 text-slate-500 text-[10px] uppercase tracking-wider z-10">
                                    <tr>
                                        <th class="p-2.5">Input Domain Target</th>
                                        <th class="p-2.5">Duration</th>
                                        <th class="p-2.5">Status</th>
                                        <th class="p-2.5 cursor-help" title="Active VAE Backpropagation Loss computed per batch-size-1 execution pair">Pair Loss (ML) ℹ️</th>
                                        <th class="p-2.5 cursor-help" title="Stochastic latent space sample vector z sampled via reparameterization">Latent Z (ML) ℹ️</th>
                                        <th class="p-2.5 cursor-help" title="Gradient magnitude update applied via backward pass">Grad Norm (ML) ℹ️</th>
                                        <th class="p-2.5">Details</th>
                                    </tr>
                                </thead>
                                <tbody id="fuzz-body" class="divide-y divide-slate-100">
                                    <tr><td colspan="7" class="p-4 text-center text-slate-400 italic">Initializing concurrent worker pool...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>

                <!-- Diffusion Generated Section -->
                <section class="space-y-2">
                    <div class="flex justify-between items-center">
                        <h2 class="text-xs font-bold text-slate-700 uppercase tracking-wider">Diffusion-Generated Optimized Input Domains</h2>
                        <input id="search-gen-input" type="text" placeholder="Fuzzy search generated domains..." class="px-2.5 py-1 w-64 bg-white border border-slate-200 rounded text-xs focus:outline-none focus:border-slate-400" />
                    </div>
                    <div class="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden">
                        <div class="max-h-72 overflow-y-auto no-scrollbar">
                            <table class="w-full text-left border-collapse">
                                <thead class="sticky top-0 bg-slate-50 border-b border-slate-200 text-slate-500 text-[10px] uppercase tracking-wider z-10">
                                    <tr>
                                        <th class="p-2.5">Generated Target Domain</th>
                                        <th class="p-2.5">Predicted Duration</th>
                                        <th class="p-2.5 cursor-help" title="Reverse diffusion step output guiding domain synthesis">Diffusion State (ML) ℹ️️</th>
                                        <th class="p-2.5">Type</th>
                                    </tr>
                                </thead>
                                <tbody id="gen-body" class="divide-y divide-slate-100">
                                    <tr><td colspan="4" class="p-4 text-center text-slate-400 italic">Awaiting initial diffusion pair ingestion...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>
            </div>
        `;

        const statusBadge = container.querySelector('#status-badge');
        const fuzzInput = container.querySelector('#search-fuzz-input');
        const genInput = container.querySelector('#search-gen-input');

        fuzzInput.oninput = (e) => setSearchFuzz(e.target.value.toLowerCase());
        genInput.oninput = (e) => setSearchGen(e.target.value.toLowerCase());

        setInterval(() => {
            statusBadge.textContent = state.status === 'Complete' ? 'Complete' : 'Running';
            statusBadge.className = state.status === 'Complete' ? 'text-emerald-600 font-semibold' : 'text-amber-600 font-semibold';

            const filteredFuzz = state.results.filter(row => 
                row.target.toLowerCase().includes(searchFuzz()) || 
                row.status.toLowerCase().includes(searchFuzz()) || 
                String(row.duration_us).includes(searchFuzz()) ||
                String(row.pairLoss).includes(searchFuzz()) ||
                row.details.toLowerCase().includes(searchFuzz())
            );

            const fuzzBody = container.querySelector('#fuzz-body');
            if (fuzzBody) {
                if (state.results.length === 0) {
                    fuzzBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-slate-400 italic">Scanning all system binaries concurrently...</td></tr>`;
                } else if (filteredFuzz.length === 0) {
                    fuzzBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-slate-400 italic">No matching fuzzing records found.</td></tr>`;
                } else {
                    fuzzBody.innerHTML = filteredFuzz.map(row => `
                        <tr class="hover:bg-slate-50/50">
                            <td class="p-2.5 font-medium text-slate-700">${row.target}</td>
                            <td class="p-2.5 font-mono text-slate-600">${row.duration_us || 0} μs</td>
                            <td class="p-2.5"><span class="px-2 py-0.5 rounded text-[9px] font-semibold ${row.status.includes('WORKED') ? 'bg-emerald-50 text-emerald-700' : 'bg-rose-50 text-rose-700'}">${row.status}</span></td>
                            <td class="p-2.5 font-mono text-indigo-600 font-bold" title="Backprop loss computed">${row.pairLoss}</td>
                            <td class="p-2.5 font-mono text-slate-500" title="Latent z vector">${row.latentZ}</td>
                            <td class="p-2.5 font-mono text-slate-500" title="Gradient norm">${row.gradNorm}</td>
                            <td class="p-2.5 text-slate-400">${row.details}</td>
                        </tr>
                    `).join('');
                }
            }

            const filteredGen = state.generated.filter(row => 
                row.target.toLowerCase().includes(searchGen()) || 
                row.status.toLowerCase().includes(searchGen()) || 
                String(row.predictedDuration).includes(searchGen())
            );

            const genBody = container.querySelector('#gen-body');
            if (genBody) {
                if (state.generated.length === 0) {
                    genBody.innerHTML = `<tr><td colspan="4" class="p-4 text-center text-slate-400 italic">Awaiting initial diffusion pair ingestion...</td></tr>`;
                } else if (filteredGen.length === 0) {
                    genBody.innerHTML = `<tr><td colspan="4" class="p-4 text-center text-slate-400 italic">No matching generated domains found.</td></tr>`;
                } else {
                    genBody.innerHTML = filteredGen.map(row => `
                        <tr class="hover:bg-slate-50/50">
                            <td class="p-2.5 font-medium text-slate-700">${row.target}</td>
                            <td class="p-2.5 font-mono text-slate-600">${row.predictedDuration} μs</td>
                            <td class="p-2.5 font-mono text-indigo-600" title="Diffusion state z">${row.diffusionState || 'z ~ N(0,I)'}</td>
                            <td class="p-2.5"><span class="px-2 py-0.5 rounded text-[9px] font-semibold bg-sky-50 text-sky-700">${row.status}</span></td>
                        </tr>
                    `).join('');
                }
            }
        }, 200);

        return container;
    })();
}

render(() => App(), document.getElementById('app'));