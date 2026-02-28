import { useParams } from 'react-router-dom';

export default function VerificationScreen() {
  const { id } = useParams();
  return <main style={{ maxWidth: 900, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>Verification report: {id}</main>;
}
