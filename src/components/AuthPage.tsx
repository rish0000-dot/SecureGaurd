import React, { useState, useEffect } from 'react';
import { ArrowLeft, Check } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import './AuthPage.css';

interface AuthPageProps {
  defaultMode: 'signup' | 'login';
}

const AuthPage: React.FC<AuthPageProps> = ({ defaultMode }) => {
  const [isLogin, setIsLogin] = useState(defaultMode === 'login');
  const [agreed, setAgreed] = useState(false);
  const location = useLocation();

  // Update mode if URL changes while component is mounted
  useEffect(() => {
    setIsLogin(defaultMode === 'login');
  }, [defaultMode, location.pathname]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    console.log(`${isLogin ? 'Login' : 'Signup'} submitted`);
  };

  return (
    <div className="auth-container">
      <Link to="/" className="back-link">
        <ArrowLeft size={16} />
        <span>Return to Home</span>
      </Link>
      
      <div className="auth-card glass-card">
        <div className="auth-header">
          <Link to="/" className="auth-brand">
            SecureGuard
          </Link>
          <h1 className="auth-title">
            {isLogin ? 'Welcome back' : 'Create an account'}
          </h1>
          <p className="auth-subtitle">
            {isLogin 
              ? 'Enter your details to access your dashboard.' 
              : 'Start your 14-day free trial. No credit card required.'}
          </p>
        </div>

        <form className="auth-form" onSubmit={handleSubmit} autoComplete="off">
          {!isLogin && (
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="firstName">First Name</label>
                <input type="text" id="firstName" name="firstName_noautofill" autoComplete="off" placeholder="Jane" required={!isLogin} />
              </div>
              <div className="form-group">
                <label htmlFor="lastName">Last Name</label>
                <input type="text" id="lastName" name="lastName_noautofill" autoComplete="off" placeholder="Doe" required={!isLogin} />
              </div>
            </div>
          )}

          <div className="form-group">
            <label htmlFor="email">Work Email</label>
            <input type="email" id="email" name="email_noautofill" autoComplete="off" placeholder="jane@company.com" required />
          </div>

          <div className="form-group">
            <div className="label-row">
              <label htmlFor="password">Password</label>
              {isLogin && <a href="#" className="forgot-password">Forgot password?</a>}
            </div>
            <input type="password" id="password" name="new-password" autoComplete="new-password" placeholder="••••••••" required />
          </div>

          {!isLogin && (
            <div className="checkbox-group" onClick={() => setAgreed(!agreed)}>
              <div className={`checkbox ${agreed ? 'checked' : ''}`}>
                {agreed && <Check size={12} strokeWidth={3} />}
              </div>
              <span className="checkbox-label">
                I agree to the <a href="#">Terms of Service</a> & <a href="#">Privacy Policy</a>
              </span>
            </div>
          )}

          <button type="submit" className="auth-submit-btn">
            {isLogin ? 'Sign In' : 'Start Free Trial'}
          </button>
        </form>

        <div className="auth-footer">
          <p>
            {isLogin ? "Don't have an account?" : "Already have an account?"}
            <button 
              className="toggle-mode-btn" 
              onClick={() => setIsLogin(!isLogin)}
            >
              {isLogin ? 'Sign up' : 'Log in'}
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

export default AuthPage;
