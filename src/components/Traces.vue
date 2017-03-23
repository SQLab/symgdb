<template>
  <div>
		<trace v-for="item in items" :key=item.id :item=item>
		</trace>
	</div>
</template>
<script>
import Trace from './Trace.vue'
export default {
	name: 'Traces',
  props: ['items'],
  components:
  { "trace": Trace}
}
</script>
