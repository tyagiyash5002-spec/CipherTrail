import { Slot } from '@radix-ui/react-slot';
import { cva } from 'class-variance-authority';
import { cn } from '../../lib/utils';
const variants = cva('btn', { variants: { variant: { default: 'btn-primary', outline: 'btn-outline', ghost: 'btn-ghost', destructive: 'btn-danger' }, size: { default: '', icon: 'btn-icon', sm: 'btn-small' } }, defaultVariants: { variant: 'default', size: 'default' } });
export function Button({ className, variant, size, asChild = false, ...props }) { const Comp = asChild ? Slot : 'button'; return <Comp className={cn(variants({ variant, size }), className)} {...props}/>; }
