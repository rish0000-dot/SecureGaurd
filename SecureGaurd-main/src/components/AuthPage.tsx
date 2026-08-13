import React, { useState, useEffect } from 'react';
import { ArrowLeft, Check, Loader2, Mail, ArrowRight } from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './AuthPage.css';

interface AuthPageProps {
  defaultMode: 'signup' | 'login' | 'forgot';
}

const API = '/api/auth';

const AuthPage: React.FC<AuthPageProps> = ({ defaultMode }) => {
  const [mode, setMode]       = useState<'signup' | 'login' | 'forgot' | 'reset'>(defaultMode);
  const [agreed, setAgreed]   = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const [success, setSuccess] = useState('');

  // Form fields
  const [firstName, setFirstName] = useState('');
  const [lastName,  setLastName]  = useState('');
  const [email,     setEmail]     = useState('');
  const [password,  setPassword]  = useState('');
  const [resetToken,  setResetToken]  = useState('');
  const [newPassword, setNewPassword] = useState('');

  const location = useLocation();
  const navigate  = useNavigate();
  const { login, register } = useAuth();

  useEffect(() => {
    setMode(defaultMode);
    setError('');
    setSuccess('');
  }, [defaultMode, location.pathname]);

  // ── Login / Register ────────────────────────────────────────────────────────
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (mode === 'signup' && !agreed) {
      setError('You must agree to the Terms of Service to continue.');
      return;
    }

    setLoading(true);
    try {
      if (mode === 'login') {
        await login(email, password);
      } else {
        await register(firstName, lastName, email, password);
      }
      setSuccess(mode === 'login' ? 'Login successful! Redirecting…' : 'Account created! Redirecting…');
      setTimeout(() => navigate('/dashboard'), 1200);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong.');
    } finally {
      setLoading(false);
    }
  };

  // ── Forgot Password ─────────────────────────────────────────────────────────
  const handleForgotSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      const res  = await fetch(`${API}/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message);
      setSuccess('Reset token generated! Check the response or your email.');
      // In dev: auto-fill token from response
      if (data.resetToken) setResetToken(data.resetToken);
      setTimeout(() => setMode('reset'), 1500);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong.');
    } finally {
      setLoading(false);
    }
  };

  // ── Reset Password ──────────────────────────────────────────────────────────
  const handleResetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    setLoading(true);
    try {
      const res  = await fetch(`${API}/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: resetToken, newPassword }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message);
      setSuccess('Password reset! Redirecting to login…');
      setTimeout(() => { setMode('login'); setSuccess(''); }, 2000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong.');
    } finally {
      setLoading(false);
    }
  };

  // ── Titles ──────────────────────────────────────────────────────────────────
  const titles = {
    login:  { h: 'Welcome back',         sub: 'Enter your details to access your dashboard.' },
    signup: { h: 'Create an account',    sub: 'Start your 14-day free trial. No credit card required.' },
    forgot: { h: 'Forgot your password?',sub: 'Enter your email and we\'ll send a reset link.' },
    reset:  { h: 'Reset your password',  sub: 'Enter the reset token and your new password.' },
  };
  const { h, sub } = titles[mode];

  return (
    <div className="auth-container">
      <Link to="/" className="back-link">
        <ArrowLeft size={16} />
        <span>Return to Home</span>
      </Link>

      <div className="auth-card glass-card">
        <div className="auth-header">
          <Link to="/" className="auth-brand">SecureGuard</Link>
          <h1 className="auth-title">{h}</h1>
          <p className="auth-subtitle">{sub}</p>
        </div>

        {error   && <div className="auth-alert auth-alert--error">{error}</div>}
        {success && <div className="auth-alert auth-alert--success">{success}</div>}

        {/* ── Login / Register ─── */}
        {(mode === 'login' || mode === 'signup') && (
          <form className="auth-form" onSubmit={handleAuthSubmit} autoComplete="off">
            {mode === 'signup' && (
              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="firstName">First Name</label>
                  <input type="text" id="firstName" placeholder="Jane" value={firstName}
                    onChange={e => setFirstName(e.target.value)} required autoComplete="off" />
                </div>
                <div className="form-group">
                  <label htmlFor="lastName">Last Name</label>
                  <input type="text" id="lastName" placeholder="Doe" value={lastName}
                    onChange={e => setLastName(e.target.value)} required autoComplete="off" />
                </div>
              </div>
            )}

            <div className="form-group">
              <label htmlFor="email">Work Email</label>
              <input type="email" id="email" placeholder="jane@company.com" value={email}
                onChange={e => setEmail(e.target.value)} required autoComplete="off" />
            </div>

            <div className="form-group">
              <div className="label-row">
                <label htmlFor="password">Password</label>
                {mode === 'login' && (
                  <button type="button" className="forgot-password" onClick={() => setMode('forgot')}>
                    Forgot password?
                  </button>
                )}
              </div>
              <input type="password" id="password" placeholder="••••••••" value={password}
                onChange={e => setPassword(e.target.value)} required autoComplete="new-password"
                minLength={8} />
            </div>

            {mode === 'signup' && (
              <div className="checkbox-group" onClick={() => setAgreed(!agreed)}>
                <div className={`checkbox ${agreed ? 'checked' : ''}`}>
                  {agreed && <Check size={12} strokeWidth={3} />}
                </div>
                <span className="checkbox-label">
                  I agree to the <a href="#">Terms of Service</a> &amp; <a href="#">Privacy Policy</a>
                </span>
              </div>
            )}

            <button type="submit" className="auth-submit-btn" disabled={loading}>
              {loading
                ? <span className="btn-loading"><Loader2 size={16} className="spin" /> Processing…</span>
                : mode === 'login' ? 'Sign In' : 'Start Free Trial'
              }
            </button>
          </form>
        )}

        {/* ── Forgot Password ─── */}
        {mode === 'forgot' && (
          <form className="auth-form" onSubmit={handleForgotSubmit} autoComplete="off">
            <div className="form-group">
              <label htmlFor="forgot-email">Your Email</label>
              <input type="email" id="forgot-email" placeholder="jane@company.com" value={email}
                onChange={e => setEmail(e.target.value)} required />
            </div>
            <button type="submit" className="auth-submit-btn" disabled={loading}>
              {loading
                ? <span className="btn-loading"><Loader2 size={16} className="spin" /> Sending…</span>
                : <><Mail size={15} /> Send Reset Link</>
              }
            </button>
            <button type="button" className="toggle-mode-btn" style={{ marginTop: '0.5rem' }}
              onClick={() => setMode('login')}>
              ← Back to Login
            </button>
          </form>
        )}

        {/* ── Reset Password ─── */}
        {mode === 'reset' && (
          <form className="auth-form" onSubmit={handleResetSubmit} autoComplete="off">
            <div className="form-group">
              <label htmlFor="reset-token">Reset Token</label>
              <input type="text" id="reset-token" placeholder="Paste token from email" value={resetToken}
                onChange={e => setResetToken(e.target.value)} required />
            </div>
            <div className="form-group">
              <label htmlFor="new-password">New Password</label>
              <input type="password" id="new-password" placeholder="Min 8 characters" value={newPassword}
                onChange={e => setNewPassword(e.target.value)} required minLength={8} />
            </div>
            <button type="submit" className="auth-submit-btn" disabled={loading}>
              {loading
                ? <span className="btn-loading"><Loader2 size={16} className="spin" /> Resetting…</span>
                : <><ArrowRight size={15} /> Reset Password</>
              }
            </button>
          </form>
        )}

        {/* ── Footer toggle ─── */}
        {(mode === 'login' || mode === 'signup') && (
          <div className="auth-footer">
            <p>
              {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}
              <button className="toggle-mode-btn"
                onClick={() => { setMode(mode === 'login' ? 'signup' : 'login'); setError(''); setSuccess(''); }}>
                {mode === 'login' ? 'Sign up' : 'Log in'}
              </button>
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AuthPage;
