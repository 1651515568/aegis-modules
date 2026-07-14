import { defineCapability } from '@/capabilities/_shared/defineCapability'
import meta from './meta.json'
import View from './View'

export const manifest = defineCapability(meta, View)
