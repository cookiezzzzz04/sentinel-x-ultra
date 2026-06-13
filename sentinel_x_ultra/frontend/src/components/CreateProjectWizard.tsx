import { useState, useRef } from 'react';

interface WizardProps {
  defaultName?: string;
  onComplete: (
    name: string,
    description: string,
    folder: string,
    projectType: 'bug-bounty' | 'full-assessment',
  ) => void;
  onCancel: () => void;
}

type Step = 'location' | 'type' | 'summary';

export function CreateProjectWizard({ defaultName, onComplete, onCancel }: WizardProps) {
  const [step, setStep] = useState<Step>('location');
  const [name, setName] = useState(defaultName || '');
  const [description, setDescription] = useState('');
  const [folder, setFolder] = useState('');
  const [projectType, setProjectType] = useState<'bug-bounty' | 'full-assessment' | null>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const handleBrowse = async () => {
    // Try showDirectoryPicker() first (Chrome 86+, Edge)
    try {
      const handle = await (window as any).showDirectoryPicker();
      const folderName = handle.name;

      // Set the folder name in the input immediately — never leave it blank
      setFolder(folderName);

      // Read all files from the directory and upload them (background)
      const files: { path: string; content: string }[] = [];
      const supportedExt = new Set([
        '.py',
        '.js',
        '.ts',
        '.jsx',
        '.tsx',
        '.java',
        '.go',
        '.rb',
        '.php',
        '.sql',
        '.cs',
        '.c',
        '.cpp',
        '.h',
        '.hpp',
        '.yaml',
        '.yml',
        '.json',
        '.xml',
        '.html',
        '.css',
        '.txt',
        '.md',
        '.env',
        '.conf',
        '.ini',
      ]);
      const skipDirs = new Set([
        'node_modules',
        '.git',
        '__pycache__',
        'venv',
        '.venv',
        'dist',
        'build',
        '.idea',
        '.vscode',
      ]);

      async function readDir(dirHandle: any, basePath: string = '') {
        for await (const entry of dirHandle.values()) {
          if (entry.kind === 'file') {
            const ext = '.' + entry.name.split('.').pop()?.toLowerCase();
            if (supportedExt.has(ext)) {
              const file = await entry.getFile();
              const content = await file.text();
              files.push({ path: basePath + entry.name, content });
            }
          } else if (entry.kind === 'directory') {
            const dirName = entry.name;
            if (!skipDirs.has(dirName)) {
              await readDir(entry, basePath + dirName + '/');
            }
          }
        }
      }

      await readDir(handle);

      if (files.length > 0) {
        // Upload files to server for later analysis
        try {
          await fetch('/api/projects/upload-files', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ folder_name: folderName, folder_path: folderName, files }),
          });
        } catch (e) {
          // Silent fail - folder name is still saved in input
        }
      }
    } catch (pickerErr) {
      // Fallback: use hidden <input webkitdirectory>
      if (folderInputRef.current) {
        folderInputRef.current.click();
      }
    }
  };

  const handleFolderFilesSelected = (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) {
      return;
    }
    // Extract folder name from webkitRelativePath
    const firstFile = fileList[0];
    const relativePath = firstFile.webkitRelativePath || '';
    const rootFolder = relativePath.split('/')[0];
    if (rootFolder) {
      setFolder(rootFolder);
      alert(`Selected "${rootFolder}" — type the full path above`);
    }
  };

  const isValidStep1 = name.trim().length > 0 && folder.trim().length > 0;

  const getEnabledTabs = () => {
    if (projectType === 'bug-bounty') {
      return ['overview', 'bug-bounty', 'findings', 'ai-report'];
    }
    return [
      'overview',
      'recon',
      'assets',
      'findings',
      'reports',
      'proxy',
      'intelligence',
      'analysis',
    ];
  };

  if (step === 'location') {
    return (
      <div style={{ animation: 'fadeInUp 0.3s ease' }}>
        {/* Step Indicator */}
        <div
          style={{ display: 'flex', gap: '8px', marginBottom: '32px', justifyContent: 'center' }}
        >
          {(['location', 'type', 'summary'] as const).map((s: Step, i) => (
            <div key={s} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '50%',
                  background:
                    (step as string) === s
                      ? 'linear-gradient(135deg, #00d4ff, #00ff88)'
                      : s === 'location'
                        ? '#00d4ff'
                        : 'rgba(255,255,255,0.1)',
                  color: (step as string) === s || s === 'location' ? '#000' : '#666',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '13px',
                  fontWeight: '700',
                }}
              >
                {s === 'location' ? '1' : s === 'type' ? '2' : '3'}
              </div>
              <span
                style={{
                  fontSize: '12px',
                  color: step === s ? '#00d4ff' : '#666',
                  fontWeight: step === s ? '600' : '400',
                }}
              >
                {s === 'location' ? 'Location' : s === 'type' ? 'Type' : 'Summary'}
              </span>
              {i < 2 && (
                <div
                  style={{
                    width: '40px',
                    height: '2px',
                    background: step !== 'location' ? '#00d4ff' : 'rgba(255,255,255,0.1)',
                  }}
                />
              )}
            </div>
          ))}
        </div>

        <h2
          style={{ fontSize: '22px', fontWeight: 'bold', marginBottom: '8px', textAlign: 'center' }}
        >
          Create New Project
        </h2>
        <p style={{ fontSize: '13px', color: '#888', textAlign: 'center', marginBottom: '32px' }}>
          Choose where your project will live and give it a name
        </p>

        <div style={{ maxWidth: '480px', margin: '0 auto' }}>
          {/* Project Name */}
          <div style={{ marginBottom: '20px' }}>
            <label
              style={{
                display: 'block',
                marginBottom: '8px',
                color: '#888',
                fontSize: '13px',
                fontWeight: '600',
              }}
            >
              Project Name <span style={{ color: '#ff4444' }}>*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Security Assessment"
              autoFocus
              style={{
                width: '100%',
                padding: '14px 16px',
                background: 'rgba(0,0,0,0.3)',
                border: `1px solid ${name.trim() ? 'rgba(0,212,255,0.3)' : 'rgba(255,255,255,0.1)'}`,
                borderRadius: '10px',
                color: '#fff',
                fontSize: '15px',
                transition: 'border-color 0.2s',
              }}
            />
          </div>
          {/* Project Description */}
          <div style={{ marginBottom: '20px' }}>
            <label
              style={{
                display: 'block',
                marginBottom: '8px',
                color: '#888',
                fontSize: '13px',
                fontWeight: '600',
              }}
            >
              Description <span style={{ color: '#666' }}>(optional)</span>
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description of the target and assessment scope..."
              rows={3}
              style={{
                width: '100%',
                padding: '14px 16px',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '10px',
                color: '#fff',
                fontSize: '13px',
                resize: 'vertical',
                fontFamily: 'inherit',
              }}
            />
          </div>{' '}
          {/* Folder Selection */}
          <div style={{ marginBottom: '28px' }}>
            <label
              style={{
                display: 'block',
                marginBottom: '8px',
                color: '#888',
                fontSize: '13px',
                fontWeight: '600',
              }}
            >
              Project Folder <span style={{ color: '#ff4444' }}>*</span>
            </label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                value={folder}
                onChange={(e) => setFolder(e.target.value)}
                placeholder="C:/Projects/your-project-folder"
                style={{
                  flex: 1,
                  padding: '14px 16px',
                  background: 'rgba(0,0,0,0.3)',
                  border: `1px solid ${folder.trim() ? 'rgba(0,212,255,0.3)' : 'rgba(255,255,255,0.1)'}`,
                  borderRadius: '10px',
                  color: '#fff',
                  fontSize: '13px',
                  fontFamily: 'monospace',
                }}
              />
              <input
                ref={folderInputRef}
                type="file"
                style={{ display: 'none' }}
                {...({ webkitdirectory: '' } as any)}
                onChange={handleFolderFilesSelected}
              />
              <button
                onClick={handleBrowse}
                style={{
                  padding: '14px 20px',
                  background: 'rgba(0,212,255,0.1)',
                  border: '1px solid rgba(0,212,255,0.3)',
                  borderRadius: '10px',
                  color: '#00d4ff',
                  cursor: 'pointer',
                  fontSize: '13px',
                  fontWeight: '600',
                  whiteSpace: 'nowrap',
                }}
              >
                📁 Browse
              </button>
            </div>
            {folder && (
              <div
                style={{
                  marginTop: '8px',
                  fontSize: '12px',
                  color: '#00ff88',
                  fontFamily: 'monospace',
                }}
              >
                📁 {folder}
              </div>
            )}
            {folder &&
              !folder.startsWith('/') &&
              !folder.includes(':/') &&
              !folder.includes(':\\') && (
                <div
                  style={{
                    marginTop: '6px',
                    fontSize: '11px',
                    color: '#ff8844',
                    padding: '6px 10px',
                    background: 'rgba(255,136,68,0.1)',
                    borderRadius: '6px',
                    border: '1px solid rgba(255,136,68,0.2)',
                  }}
                >
                  ⚠️ Replace the folder name above with the <strong>full path</strong> (e.g.,{' '}
                  <code style={{ color: '#ffaa00' }}>C:/Users/.../{folder}</code>) so the server can
                  find your files
                </div>
              )}
            {folder &&
              (folder.startsWith('/') || folder.includes(':/') || folder.includes(':\\')) && (
                <div
                  style={{
                    marginTop: '6px',
                    fontSize: '11px',
                    color: '#00ff88',
                    padding: '6px 10px',
                    background: 'rgba(0,255,136,0.1)',
                    borderRadius: '6px',
                    border: '1px solid rgba(0,255,136,0.2)',
                  }}
                >
                  ✓ Full path looks good — Bug Bounty scan will read files from this folder
                </div>
              )}
          </div>
          {/* Buttons */}
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button
              onClick={onCancel}
              style={{
                padding: '14px 24px',
                background: 'transparent',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '10px',
                color: '#888',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '600',
              }}
            >
              Cancel
            </button>
            <button
              onClick={() => setStep('type')}
              disabled={!isValidStep1}
              style={{
                padding: '14px 28px',
                background: isValidStep1
                  ? 'linear-gradient(135deg, #00d4ff, #00ff88)'
                  : 'rgba(255,255,255,0.1)',
                border: 'none',
                borderRadius: '10px',
                color: isValidStep1 ? '#000' : '#666',
                cursor: isValidStep1 ? 'pointer' : 'not-allowed',
                fontSize: '14px',
                fontWeight: '700',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              Next →
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (step === 'type') {
    return (
      <div style={{ animation: 'fadeInUp 0.3s ease' }}>
        {/* Step Indicator */}
        <div
          style={{ display: 'flex', gap: '8px', marginBottom: '32px', justifyContent: 'center' }}
        >
          {(['location', 'type', 'summary'] as Step[]).map((s) => (
            <div key={s} style={{ display: 'flex', alignItems: 'center' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '50%',
                  background:
                    s === 'type'
                      ? 'linear-gradient(135deg, #00d4ff, #00ff88)'
                      : 'rgba(255,255,255,0.1)',
                  color: s === 'type' ? '#000' : '#666',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '13px',
                  fontWeight: '700',
                }}
              >
                {s === 'location' ? '✓' : s === 'type' ? '2' : '3'}
              </div>
            </div>
          ))}
        </div>

        <h2
          style={{ fontSize: '22px', fontWeight: 'bold', marginBottom: '8px', textAlign: 'center' }}
        >
          Project Type
        </h2>
        <p style={{ fontSize: '13px', color: '#888', textAlign: 'center', marginBottom: '32px' }}>
          Choose the type of security assessment you want to perform
        </p>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '20px',
            maxWidth: '700px',
            margin: '0 auto',
          }}
        >
          {/* Bug Bounty Card */}
          <div
            onClick={() => setProjectType('bug-bounty')}
            style={{
              background:
                projectType === 'bug-bounty'
                  ? 'rgba(170, 136, 255, 0.15)'
                  : 'rgba(15, 15, 26, 0.95)',
              border:
                projectType === 'bug-bounty'
                  ? '2px solid rgba(170, 136, 255, 0.5)'
                  : '1px solid rgba(255,255,255,0.05)',
              borderRadius: '16px',
              padding: '28px',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              position: 'relative',
            }}
            onMouseEnter={(e) => {
              if (projectType !== 'bug-bounty') {
                e.currentTarget.style.borderColor = 'rgba(170,136,255,0.3)';
              }
            }}
            onMouseLeave={(e) => {
              if (projectType !== 'bug-bounty') {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)';
              }
            }}
          >
            <div style={{ fontSize: '48px', marginBottom: '16px', textAlign: 'center' }}>🏴</div>
            <h3
              style={{
                fontSize: '18px',
                fontWeight: 'bold',
                marginBottom: '8px',
                textAlign: 'center',
                color: projectType === 'bug-bounty' ? '#aa88ff' : '#fff',
              }}
            >
              Bug Bounty
            </h3>
            <p
              style={{
                fontSize: '13px',
                color: '#888',
                textAlign: 'center',
                marginBottom: '16px',
                lineHeight: '1.5',
              }}
            >
              Designed specifically for bug bounty programs and responsible disclosure workflows.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div
                style={{
                  fontSize: '11px',
                  color: '#666',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span style={{ color: '#00ff88' }}>✓</span> Bug Bounty panel
              </div>
              <div
                style={{
                  fontSize: '11px',
                  color: '#666',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span style={{ color: '#00ff88' }}>✓</span> Findings & Reports
              </div>
              <div
                style={{
                  fontSize: '11px',
                  color: '#666',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span style={{ color: '#ff4444' }}>✗</span> Recon & Proxy hidden
              </div>
            </div>
            {projectType === 'bug-bounty' && (
              <div
                style={{
                  position: 'absolute',
                  top: '12px',
                  right: '12px',
                  background: '#aa88ff',
                  color: '#000',
                  fontSize: '10px',
                  fontWeight: '700',
                  padding: '4px 8px',
                  borderRadius: '4px',
                }}
              >
                SELECTED
              </div>
            )}
          </div>

          {/* Full Assessment Card */}
          <div
            onClick={() => setProjectType('full-assessment')}
            style={{
              background:
                projectType === 'full-assessment'
                  ? 'rgba(0, 212, 255, 0.15)'
                  : 'rgba(15, 15, 26, 0.95)',
              border:
                projectType === 'full-assessment'
                  ? '2px solid rgba(0, 212, 255, 0.5)'
                  : '1px solid rgba(255,255,255,0.05)',
              borderRadius: '16px',
              padding: '28px',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              position: 'relative',
            }}
            onMouseEnter={(e) => {
              if (projectType !== 'full-assessment') {
                e.currentTarget.style.borderColor = 'rgba(0,212,255,0.3)';
              }
            }}
            onMouseLeave={(e) => {
              if (projectType !== 'full-assessment') {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)';
              }
            }}
          >
            <div style={{ fontSize: '48px', marginBottom: '16px', textAlign: 'center' }}>🛡️</div>
            <h3
              style={{
                fontSize: '18px',
                fontWeight: 'bold',
                marginBottom: '8px',
                textAlign: 'center',
                color: projectType === 'full-assessment' ? '#00d4ff' : '#fff',
              }}
            >
              Full Assessment
            </h3>
            <p
              style={{
                fontSize: '13px',
                color: '#888',
                textAlign: 'center',
                marginBottom: '16px',
                lineHeight: '1.5',
              }}
            >
              Designed for broader security assessments and attack-surface analysis.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div
                style={{
                  fontSize: '11px',
                  color: '#666',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span style={{ color: '#00ff88' }}>✓</span> Recon & Assets
              </div>
              <div
                style={{
                  fontSize: '11px',
                  color: '#666',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span style={{ color: '#00ff88' }}>✓</span> Proxy & Intelligence
              </div>
              <div
                style={{
                  fontSize: '11px',
                  color: '#666',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span style={{ color: '#ff4444' }}>✗</span> Bug Bounty panel hidden
              </div>
            </div>
            {projectType === 'full-assessment' && (
              <div
                style={{
                  position: 'absolute',
                  top: '12px',
                  right: '12px',
                  background: '#00d4ff',
                  color: '#000',
                  fontSize: '10px',
                  fontWeight: '700',
                  padding: '4px 8px',
                  borderRadius: '4px',
                }}
              >
                SELECTED
              </div>
            )}
          </div>
        </div>

        {/* Buttons */}
        <div
          style={{
            display: 'flex',
            gap: '12px',
            justifyContent: 'space-between',
            maxWidth: '700px',
            margin: '32px auto 0',
          }}
        >
          <button
            onClick={() => setStep('location')}
            style={{
              padding: '14px 24px',
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '10px',
              color: '#888',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '600',
            }}
          >
            ← Back
          </button>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={onCancel}
              style={{
                padding: '14px 24px',
                background: 'transparent',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '10px',
                color: '#888',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '600',
              }}
            >
              Cancel
            </button>
            <button
              onClick={() => setStep('summary')}
              disabled={!projectType}
              style={{
                padding: '14px 28px',
                background: projectType
                  ? 'linear-gradient(135deg, #00d4ff, #00ff88)'
                  : 'rgba(255,255,255,0.1)',
                border: 'none',
                borderRadius: '10px',
                color: projectType ? '#000' : '#666',
                cursor: projectType ? 'pointer' : 'not-allowed',
                fontSize: '14px',
                fontWeight: '700',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              Next →
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Summary step
  return (
    <div style={{ animation: 'fadeInUp 0.3s ease' }}>
      <div style={{ maxWidth: '500px', margin: '0 auto' }}>
        <h2
          style={{ fontSize: '22px', fontWeight: 'bold', marginBottom: '8px', textAlign: 'center' }}
        >
          Review & Create
        </h2>
        <p style={{ fontSize: '13px', color: '#888', textAlign: 'center', marginBottom: '32px' }}>
          Review your project settings before creating
        </p>

        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '16px',
            border: '1px solid rgba(255,255,255,0.05)',
            overflow: 'hidden',
            marginBottom: '24px',
          }}
        >
          <div style={{ padding: '20px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
            <div
              style={{
                fontSize: '11px',
                color: '#666',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                marginBottom: '4px',
              }}
            >
              Project Name
            </div>
            <div style={{ fontSize: '16px', fontWeight: '600' }}>{name}</div>
          </div>
          {description && (
            <div style={{ padding: '20px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
              <div
                style={{
                  fontSize: '11px',
                  color: '#666',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  marginBottom: '4px',
                }}
              >
                Description
              </div>
              <div style={{ fontSize: '14px', color: '#888' }}>{description}</div>
            </div>
          )}
          <div style={{ padding: '20px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
            <div
              style={{
                fontSize: '11px',
                color: '#666',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                marginBottom: '4px',
              }}
            >
              Project Folder
            </div>
            <div style={{ fontSize: '13px', fontFamily: 'monospace', color: '#00ff88' }}>
              {folder}
            </div>
          </div>
          <div style={{ padding: '20px' }}>
            <div
              style={{
                fontSize: '11px',
                color: '#666',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                marginBottom: '4px',
              }}
            >
              Project Type
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '20px' }}>{projectType === 'bug-bounty' ? '🏴' : '🛡️'}</span>
              <span
                style={{
                  fontSize: '16px',
                  fontWeight: '600',
                  color: projectType === 'bug-bounty' ? '#aa88ff' : '#00d4ff',
                }}
              >
                {projectType === 'bug-bounty' ? 'Bug Bounty' : 'Full Assessment'}
              </span>
            </div>
            <div style={{ fontSize: '12px', color: '#888', marginTop: '12px' }}>
              Enabled tabs:{' '}
              {getEnabledTabs()
                .map((t) => t.charAt(0).toUpperCase() + t.slice(1))
                .join(', ')}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', justifyContent: 'space-between' }}>
          <button
            onClick={() => setStep('type')}
            style={{
              padding: '14px 24px',
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '10px',
              color: '#888',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '600',
            }}
          >
            ← Back
          </button>
          <button
            onClick={() => onComplete(name, description, folder, projectType!)}
            style={{
              padding: '14px 32px',
              background: 'linear-gradient(135deg, #00d4ff, #00ff88)',
              border: 'none',
              borderRadius: '10px',
              color: '#000',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '700',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            ✨ Create Project
          </button>
        </div>
      </div>
    </div>
  );
}
