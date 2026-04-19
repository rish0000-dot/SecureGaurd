import React, { useState, useEffect } from 'react';
import { ArrowLeft, Check, Loader2 } from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import './AuthPage.css';

interface AuthPageProps {
  defaultMode: 'signup' | 'login';
}

const API_URL = 'http://localhost:5000/api/auth';

const AuthPage: React.FC<AuthPageProps> = ({ defaultMode }) => {
  const [isLogin, setIsLogin] = useState(defaultMode === 'login');
  const [agreed, setAgreed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Controlled form fields
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    setIsLogin(defaultMode === 'login');
    setError('');
    setSuccess('');
  }, [defaultMode, location.pathname]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!isLogin && !agreed) {
      setError('You must agree to the Terms of Service to continue.');
      return;
    }

    setLoading(true);

    try {
      const endpoint = isLogin ? `${API_URL}/login` : `${API_URL}/register`;
      const body = isLogin
        ? { email, password }
        : { firstName, lastName, email, password };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.message || 'Something went wrong. Please try again.');
        return;
      }

      // Store JWT token
      localStorage.setItem('sg_token', data.token);
      localStorage.setItem('sg_user', JSON.stringify(data.user));

      setSuccess(isLogin ? 'Login successful! Redirecting...' : 'Account created! Redirecting...');

      // Redirect after short delay so user sees the success message
      setTimeout(() => navigate('/'), 1500);

    } catch {
      setError('Unable to connect to server. Please make sure the backend is running.');
    } finally {
      setLoading(false);
    }
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

        {error && <div className="auth-alert auth-alert--error">{error}</div>}
        {success && <div className="auth-alert auth-alert--success">{success}</div>}

        <form className="auth-form" onSubmit={handleSubmit} autoComplete="off">
          {!isLogin && (
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="firstName">First Name</label>
                <input
                  type="text"
                  id="firstName"
                  name="firstName_x"
                  autoComplete="off"
                  placeholder="Jane"
                  value={firstName}
                  onChange={e => setFirstName(e.target.value)}
                  required={!isLogin}
                />
              </div>
              <div className="form-group">
                <label htmlFor="lastName">Last Name</label>
                <input
                  type="text"
                  id="lastName"
                  name="lastName_x"
                  autoComplete="off"
                  placeholder="Doe"
                  value={lastName}
                  onChange={e => setLastName(e.target.value)}
                  required={!isLogin}
                />
              </div>
            </div>
          )}

          <div className="form-group">
            <label htmlFor="email">Work Email</label>
            <input
              type="email"
              id="email"
              name="email_x"
              autoComplete="off"
              placeholder="jane@company.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <div className="label-row">
              <label htmlFor="password">Password</label>
              {isLogin && <a href="#" className="forgot-password">Forgot password?</a>}
            </div>
            <input
              type="password"
              id="password"
              name="new-password"
              autoComplete="new-password"
              placeholder="••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
            />
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

          <button type="submit" className="auth-submit-btn" disabled={loading}>
            {loading
              ? <span className="btn-loading"><Loader2 size={16} className="spin" /> Processing...</span>
              : isLogin ? 'Sign In' : 'Start Free Trial'
            }
          </button>
        </form>

        <div className="auth-footer">
          <p>
            {isLogin ? "Don't have an account?" : "Already have an account?"}
            <button
              className="toggle-mode-btn"
              onClick={() => { setIsLogin(!isLogin); setError(''); setSuccess(''); }}
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
