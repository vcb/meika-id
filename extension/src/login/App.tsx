import React, { useState, useEffect } from 'react';
import { withBackgroundAPI } from '../api-wrapper';

enum LoginStep {
  Initial,
  Generating,
  Proving,
  Complete,
  Error
}

interface LoginRequest {
  domain: string;
  origin: string;
  challenge: string;
}

const App: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [loginRequest, setLoginRequest] = useState<LoginRequest | null>(null);
  const [currentStep, setCurrentStep] = useState<LoginStep>(LoginStep.Initial);
  const [isError, setIsError] = useState<boolean>(false);
  const [failedAtStep, setFailedAtStep] = useState<LoginStep | null>(null);

  useEffect(() => {
    const fetchLoginRequest = async () => {
      try {
        const response = await withBackgroundAPI(api => api.getLoginRequest());
        if (response.success && response.loginRequest) {
          setLoginRequest(response.loginRequest);
        } else {
          setError('No login request found');
        }
      } catch (err) {
        console.error('Error fetching login request:', err);
        setError('Error fetching login request');
      }
    };
    
    fetchLoginRequest();
  }, []);
  
  const handleConfirm = async () => {
    setLoading(true);
    
    try {
      setCurrentStep(LoginStep.Generating);

      const respInputs = await withBackgroundAPI(async api => {
        const inputs = await api.confirmLogin();
        return inputs;
      });
      if (!respInputs.success) {
        setFailedAtStep(LoginStep.Generating);
        setIsError(true);
        setError(respInputs.error || 'Failed to prepare login data');
        return;
      }
      const inputs = respInputs.inputs;
      if (!inputs) {
        setFailedAtStep(LoginStep.Generating);
        setIsError(true);
        setError('No inputs found');
        return;
      }
      
      setCurrentStep(LoginStep.Proving);
      const respProof = await withBackgroundAPI(async api => {
        const proof = await api.fullProveLogin(inputs);
        return proof;
      });
      if (!respProof.success) {
        setFailedAtStep(LoginStep.Proving);
        setIsError(true);
        setError(respProof.error || 'Failed to generate proof');
        return;
      }
      
      setCurrentStep(LoginStep.Complete);
      
      // TODO: bad UX?
      setTimeout(() => {
        window.close();
      }, 500);

    } catch (err: any) {
      console.error('Error confirming login:', err);
      setFailedAtStep(currentStep);
      setIsError(true);
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };
  
  const handleCancel = () => {
    window.close();
  };
  
  // Helper function to determine step appearance
  const getStepStatus = (step: LoginStep) => {
    if (isError) {
      if (step < failedAtStep!) {
        return { isActive: false, isCompleted: true, isError: false };
      } else if (step === failedAtStep) {
        return { isActive: false, isCompleted: false, isError: true };
      } else {
        return { isActive: false, isCompleted: false, isError: false };
      }
    } else {
      return { 
        isActive: step === currentStep,
        isCompleted: step < currentStep,
        isError: false
      };
    }
  };
  
  if (error && isError && currentStep === LoginStep.Initial) {
    return (
      <div className="login-container">
        <div className="login-screen">
          <div className="login-card">
            <h1>Login Error</h1>
            <div className="error-message">{error}</div>
            <button className="cancel-button" onClick={handleCancel}>
              Close
            </button>
          </div>
        </div>
      </div>
    );
  }
  
  return (
    <div className="login-container">
      <div className="login-screen">
        <div className="login-card">
          <h1>Meika ID Login</h1>
          
          {currentStep === LoginStep.Initial && loginRequest && (
            <>
              <div className="domain-info">
                <div className="domain-row">
                  <div className="domain-label">Domain:</div>
                  <div className="domain-value">{loginRequest.domain}</div>
                </div>
                <div className="domain-row">
                  <div className="domain-label">Origin:</div>
                  <div className="domain-value">{loginRequest.origin}</div>
                </div>
              </div>
              
              <p>
                The site above is requesting to login with your Meikä ID.
                <br />
                <br />
                Do you want to proceed?
              </p>
              
              <button 
                className="login-button" 
                onClick={handleConfirm}
                disabled={loading}
              >
                Confirm Login
              </button>
              
              <button 
                className="cancel-button" 
                onClick={handleCancel}
                disabled={loading}
              >
                Cancel
              </button>
            </>
          )}
          
          {currentStep !== LoginStep.Initial && (
            <div className="status-container">
              <div className="status-card">
                <div className="status-title">
                  {isError ? 'Login Failed' : 'Login Progress'}
                </div>
                
                <div className="status-steps">
                  {/* Generating login data step */}
                  <div className="status-step">
                    {(() => {
                      const status = getStepStatus(LoginStep.Generating);
                      return (
                        <>
                          <div className={`step-indicator ${status.isActive ? 'active' : ''} ${status.isCompleted ? 'completed' : ''} ${status.isError ? 'error' : ''}`}>
                            {status.isError ? '' : status.isCompleted ? '✓' : '1'}
                          </div>
                          <div className="step-label">Generating login data</div>
                          {status.isActive && <div className="loading-spinner" />}
                          {status.isCompleted && <div className="check-icon">✓</div>}
                          {status.isError && <div className="fail-icon">✗</div>}
                        </>
                      );
                    })()}
                  </div>
                  
                  {/* Generating proof step */}
                  <div className="status-step">
                    {(() => {
                      const status = getStepStatus(LoginStep.Proving);
                      return (
                        <>
                          <div className={`step-indicator ${status.isActive ? 'active' : ''} ${status.isCompleted ? 'completed' : ''} ${status.isError ? 'error' : ''}`}>
                            {status.isError ? '' : status.isCompleted ? '✓' : '2'}
                          </div>
                          <div className="step-label">Generating proof</div>
                          {status.isActive && <div className="loading-spinner" />}
                          {status.isCompleted && <div className="check-icon">✓</div>}
                          {status.isError && <div className="fail-icon">✗</div>}
                        </>
                      );
                    })()}
                  </div>
                  
                  {/* Completing login step */}
                  <div className="status-step">
                    {(() => {
                      const status = getStepStatus(LoginStep.Complete);
                      return (
                        <>
                          <div className={`step-indicator ${status.isActive ? 'active' : ''} ${status.isCompleted ? 'completed' : ''} ${status.isError ? 'error' : ''}`}>
                            {status.isError ? '' : status.isCompleted ? '✓' : '3'}
                          </div>
                          <div className="step-label">Completing login</div>
                          {status.isActive && <div className="loading-spinner green" />}
                          {status.isCompleted && <div className="check-icon">✓</div>}
                          {status.isError && <div className="fail-icon">✗</div>}
                        </>
                      );
                    })()}
                  </div>
                </div>
                
                {isError && (
                  <div className="error-message">
                    {error || 'An error occurred during login'}
                  </div>
                )}
                
                {isError && (
                  <button className="cancel-button" onClick={handleCancel}>
                    Close
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default App; 