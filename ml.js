export class VAEFuzzOptimizer {
    constructor(latentDim = 4, timesteps = 10) {
        this.latentDim = latentDim;
        this.timesteps = timesteps;
        this.trainingHistory = [];
        this.generatedInputs = [];
        this.weights = {
            encWeight: 0.1,
            diffWeight: 0.15,
            decWeight: 0.2
        };
    }

    _sigmoid(x) {
        return 1.0 / (1.0 + Math.exp(-Math.max(-20, Math.min(20, x))));
    }

    _reparameterize(mu, logVar) {
        const std = Math.exp(0.5 * logVar);
        const epsilon = (Math.random() + Math.random() + Math.random() - 1.5) * 1.2;
        return mu + std * epsilon;
    }

    _diffusionReverseStep(latent, t) {
        const beta = 0.01 + (t / this.timesteps) * 0.04;
        const predictedNoise = this.weights.diffWeight * latent * (t / this.timesteps);
        return (latent - Math.sqrt(beta) * predictedNoise) / Math.sqrt(1.0 - beta);
    }

    ingestPair(target, status, durationUs) {
        const isSuccess = (status.includes('WORKED') || status.includes('SKIPPED')) && durationUs <= 10000000 ? 1.0 : 0.0;
        const normalizedDuration = Math.min(1.0, durationUs / 10000000.0);
        const featureVal = (target.length / 100.0) * 0.5 + normalizedDuration * 0.5;

        const mu = featureVal * this.weights.encWeight;
        const logVar = Math.log(Math.max(0.001, Math.abs(featureVal * 0.1)));
        const z = this._reparameterize(mu, logVar);
        const reconstruction = this._sigmoid(z * this.weights.decWeight);

        const bceLoss = - (isSuccess * Math.log(Math.max(1e-7, reconstruction)) + (1.0 - isSuccess) * Math.log(Math.max(1e-7, 1.0 - reconstruction)));
        const mseLoss = Math.pow(isSuccess - reconstruction, 2);
        const totalLoss = Number((bceLoss + mseLoss).toFixed(4));

        const error = isSuccess - reconstruction;
        const gradNorm = Number(Math.abs(error * z * 0.01).toFixed(5));

        this.weights.encWeight += error * mu * 0.01;
        this.weights.decWeight += error * z * 0.01;
        this.weights.diffWeight += error * 0.005;

        this.trainingHistory.push({ target, status, durationUs, loss: totalLoss });

        let currentLatent = (Math.random() - 0.5) * 2.0;
        for (let t = this.timesteps; t > 0; t--) {
            currentLatent = this._diffusionReverseStep(currentLatent, t);
        }

        const generated = this._generateSoundInput(target, currentLatent);
        this.generatedInputs.push(generated);

        return {
            pairLoss: totalLoss,
            latentZ: Number(z.toFixed(3)),
            gradNorm: gradNorm,
            generated
        };
    }

    _generateSoundInput(baseTarget, latentZ) {
        const prefix = baseTarget.startsWith('/usr') ? '/usr/lib/' : '/lib/';
        const randHex = Math.abs(Math.floor(latentZ * 1000000)).toString(36);
        const syntheticTarget = `${prefix}libfuzz_optimized_${randHex}.so`;
        const predictedUs = Math.floor(Math.abs(this._sigmoid(latentZ)) * 9500000) + 100000;

        return {
            target: syntheticTarget,
            predictedDuration: predictedUs,
            diffusionState: Number(latentZ.toFixed(3)),
            status: 'SOUND_DIFFUSION_GENERATED'
        };
    }

    getHistory() { return this.trainingHistory; }
    getGenerated() { return this.generatedInputs; }
}