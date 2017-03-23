<template>
	<div class="col-1" @click="$root.updateTrace(item.id)">
		{{item.id}}
	</div>
</template>

<script>
export default {
	name: 'Trace',
  props: ['item']
}
</script>
