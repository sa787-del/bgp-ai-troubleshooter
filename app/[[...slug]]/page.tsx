import { Console } from '../../components/console';
export default async function Page({ params }: { params: Promise<{ slug?: string[] }> }) { const { slug } = await params; return <Console page={slug?.[0] || 'overview'} detail={slug?.[1]} />; }
