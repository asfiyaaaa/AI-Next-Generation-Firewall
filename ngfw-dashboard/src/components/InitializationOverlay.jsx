import React, { useState, useEffect } from 'react';
import './InitializationOverlay.css';

const InitializationOverlay = ({ onComplete }) => {
    const [progress, setProgress] = useState(0);
    const [step, setStep] = useState('VERIFYING_CLEARANCE');

    const steps = [
        { id: 'VERIFYING_CLEARANCE', label: 'Verifying Security Clearance...', duration: 800 },
        { id: 'DECRYPTING_PIPELINE', label: 'Decrypting Traffic Pipeline...', duration: 1000 },
        { id: 'INITIALIZING_3D_CORE', label: 'Initializing Visualization Engine...', duration: 1200 },
        { id: 'SECURE_TUNNEL_ESTABLISHED', label: 'Secure Tunnel Established.', duration: 500 }
    ];

    useEffect(() => {
        let currentStepIdx = 0;

        const runNextStep = () => {
            if (currentStepIdx >= steps.length) {
                setTimeout(onComplete, 800);
                return;
            }

            const currentStep = steps[currentStepIdx];
            setStep(currentStep.id);

            // Progress animation logic
            const startTime = Date.now();
            const stepDuration = currentStep.duration;
            const startProgress = (currentStepIdx / steps.length) * 100;
            const endProgress = ((currentStepIdx + 1) / steps.length) * 100;

            const update = () => {
                const elapsed = Date.now() - startTime;
                const ratio = Math.min(elapsed / stepDuration, 1);
                setProgress(startProgress + (endProgress - startProgress) * ratio);

                if (ratio < 1) {
                    requestAnimationFrame(update);
                } else {
                    currentStepIdx++;
                    setTimeout(runNextStep, 300);
                }
            };

            requestAnimationFrame(update);
        };

        runNextStep();
    }, []);

    return (
        <div className="init-overlay">
            <div className="init-content">
                <div className="cube-container">
                    <div className="cube">
                        <div className="face front">🛡️</div>
                        <div className="face back">🛡️</div>
                        <div className="face right">📡</div>
                        <div className="face left">📡</div>
                        <div className="face top">🏢</div>
                        <div className="face bottom">🏢</div>
                    </div>
                </div>

                <div className="init-text">
                    <h2>SYSTEM INITIALIZATION</h2>
                    <div className="step-label">{steps.find(s => s.id === step)?.label}</div>
                </div>

                <div className="progress-bar-container">
                    <div className="progress-bar" style={{ width: `${progress}%` }}></div>
                </div>

                <div className="init-footer">
                    RSA-4096 ENCRYPTED | NATIONAL CYBER DEFENSE | 256-BIT AUTH
                </div>
            </div>

            <div className="holographic-lines"></div>
        </div>
    );
};

export default InitializationOverlay;
