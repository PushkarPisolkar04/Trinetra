@app.route('/progress/<scan_id>')
def progress_stream(scan_id):
    """Server-Sent Events endpoint for real-time progress"""
    def generate():
        if scan_id in progress_queues:
            queue = progress_queues[scan_id]
            while True:
                try:
                    # Wait for progress update with timeout
                    progress = queue.get(timeout=30)
                    yield f"data: {json.dumps(progress)}\n\n"
                    
                    # If complete, stop streaming
                    if progress.get('percent') == 100:
                        break
                except:
                    # Timeout or error, stop streaming
                    break
    
    return Response(generate(), mimetype='text/event-stream')
